import fs from "fs";
import path from "path";
import { Plugin } from "vite";
import stripAnsi from "strip-ansi";

const LOGGING_SERVER_URL = "http://localhost:9000";

function reportToLoggingServer(data: string) {
    if (!LOGGING_SERVER_URL) return;
    try {
      fetch(LOGGING_SERVER_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          origin: "frontend",
          data
        }),
      }).catch(e => console.error("Failed to send log to remote server:", e));
    } catch (e) {
      console.error("Failed to send log to remote server:", e);
    }
}

function handlePreTransformError(message: string, logFile: string, level: "ERROR" | "WARN" | "INFO") {
    const timestamp = new Date().toISOString();
    fs.appendFileSync(
        logFile,
        `[${timestamp}] [${level}] ${message}\n`
    )
    if (level === "ERROR") {
        reportToLoggingServer(message);
    }
}

export function preTransformLogger(original: Logger, logFile: string): Logger {
  return {
    ...original,
    error(msg) {
        handlePreTransformError(msg, logFile, "ERROR");
    },

    info(msg) {
        handlePreTransformError(msg, logFile, "INFO");
    },

    warn(msg) {
        handlePreTransformError(msg, logFile, "WARN");
    },

    warnOnce(msg) {
        handlePreTransformError(msg, logFile, "WARN");
    },

    clearScreen(type) {
      original.clearScreen(type)
    },

    hasWarned: original.hasWarned
  }
}


export function runtimeLogger(): Plugin {
    const logsDir = path.resolve(process.cwd(), "..", "logs");
    if (!fs.existsSync(logsDir)) {
        fs.mkdirSync(logsDir, { recursive: true });
    }

    const consoleLogStream = fs.createWriteStream(path.join(logsDir, "vite.log"), { flags: "a" });

    return {
        name: "vite-logger-plugin",
        apply: "serve",
        configureServer(server) {
            const timestamp = new Date().toISOString();
            consoleLogStream.write(`[${timestamp}] [INFO] Vite dev server started\n`);

            server.ws.on("custom:log", (data) => {
                const { level, message } = data;
                const normalizedMessage = stripAnsi(message).replace("%s", "").trim();
                const timestamp = new Date().toISOString();
                consoleLogStream.write(`[${timestamp}] [${level}] ${normalizedMessage}\n`);
                if (level === "ERROR") {
                    reportToLoggingServer(normalizedMessage);
                }
            });

            server.httpServer.on("close", () => {
                const closeTimestamp = new Date().toISOString();
                consoleLogStream.write(`[${closeTimestamp}] [INFO] Vite dev server stopped\n`);
                consoleLogStream.end();
            });
        }
    };
}