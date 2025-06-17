import log from 'loglevel';

const isProd = import.meta.env?.MODE === 'production';
log.setLevel(isProd ? 'warn' : 'trace');

const originalFactory = log.methodFactory;

// Store original console methods before overriding them
const originalConsole = {
  log: console.log,
  info: console.info,
  warn: console.warn,
  error: console.error,
  debug: console.debug
};

log.methodFactory = function(methodName, logLevel, loggerName) {
    return function(...messages: { [key: string]: string }[]) {
        // Log the actual message using original console to avoid recursion
        const consoleMethod = originalConsole[methodName as keyof typeof originalConsole] || originalConsole.log;
        consoleMethod(...messages);

        // Only send logs to parent if in development mode and hot module is available
        if (isProd || !import.meta.hot) {
            return;
        }

        // Use requestAnimationFrame to batch log messages
        if (!window.requestAnimationFrame) {
            return;
        }
        
        window.requestAnimationFrame(() => {
            const formattedMessages = messages.map(msg => {
                if (msg instanceof Error) {
                    return `${msg.name}: ${msg.message}\n${msg.stack}`;
                } else if (typeof msg === 'object') {
                    try {
                        return JSON.stringify(msg);
                    } catch {
                        return String(msg);
                    }
                }
                return String(msg);
            }).join(' ');

            import.meta.hot.send('custom:log', {
                logType: 'console',
                level: methodName.toUpperCase(),
                message: formattedMessages,
            });
        });
    };
};

log.rebuild();

declare global {
    interface XMLHttpRequest {
        _logData?: {
            method: string;
            url: string;
            startTime: number;
        };
    }
}

try {
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
        const startTime = performance.now();
        const request = args[0] as RequestInfo;
        const url = typeof request === 'string' ? request : request.url;

        return originalFetch.apply(this, args)
            .then(response => {
                const duration = performance.now() - startTime;

                if (!response.ok) {
                    const message = `FETCH: ${url} failed with status ${response.status} (${duration.toFixed(2)}ms)`;
                    log.error(message);

                    if (!isProd && import.meta.hot && window.requestAnimationFrame) {
                        window.requestAnimationFrame(() => {
                            import.meta.hot.send('custom:log', {
                                logType: 'network',
                                level: 'ERROR',
                                message,
                            });
                        });
                    }
                }

                return response;
            })
            .catch((error: { message: string; }) => {
                const message = `FETCH_ERROR: ${url} - ${error.message}`;
                log.error(message);

                if (!isProd && import.meta.hot && window.requestAnimationFrame) {
                    window.requestAnimationFrame(() => {
                        import.meta.hot.send('custom:log', {
                            logType: 'network',
                            level: 'ERROR',
                            message,
                        });
                    });
                }

                throw error;
            });
    };

    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function(method: string, url: string, ...args) {
        this._logData = { method, url, startTime: 0 };
        return originalXHROpen.apply(this, [method, url, ...args]);
    };

    XMLHttpRequest.prototype.send = function(...args) {
        if (this._logData) {
            this._logData.startTime = performance.now();

            this.addEventListener('load', () => {
                const duration = performance.now() - this._logData.startTime;
                if (this.status >= 400) {
                    const message = `XHR: ${this._logData!.method} ${this._logData!.url} failed with status ${this.status} (${duration.toFixed(2)}ms)`;
                    log.error(message);

                    if (!isProd && import.meta.hot && window.requestAnimationFrame) {
                        window.requestAnimationFrame(() => {
                            import.meta.hot.send('custom:log', {
                                logType: 'network',
                                level: 'ERROR',
                                message,
                            });
                        });
                    }
                }
            });

            this.addEventListener('error', () => {
                const message = `XHR_ERROR: ${this._logData!.method} ${this._logData!.url} failed with network error`;
                log.error(message);

                if (!isProd && import.meta.hot && window.requestAnimationFrame) {
                    window.requestAnimationFrame(() => {
                        import.meta.hot.send('custom:log', {
                            logType: 'network',
                            level: 'ERROR',
                            message,
                            meta: {
                                timestamp: Date.now()
                            }
                        });
                    });
                }
            });

            this.addEventListener('timeout', () => {
                const message = `XHR_TIMEOUT: ${this._logData!.method} ${this._logData!.url} timed out`;
                log.error(message);

                if (!isProd && import.meta.hot && window.requestAnimationFrame) {
                    window.requestAnimationFrame(() => {
                        import.meta.hot.send('custom:log', {
                            logType: 'network',
                            level: 'ERROR',
                            message,
                            meta: {
                                timestamp: Date.now()
                            }
                        });
                    });
                }
            });
        }

        return originalXHRSend.apply(this, args);
    };

    // --- GLOBAL ERROR HANDLING ---
    window.addEventListener('error', (event) => {
        const { message, filename, lineno, colno, error } = event;
        const errorMessage = error
            ? `${error.name}: ${error.message}\n${error.stack}`
            : `Error: ${message} at ${filename}:${lineno}:${colno}`;

        const logMessage = `GLOBAL_ERROR: ${errorMessage}`;
        log.error(logMessage);

        if (!isProd && import.meta.hot && window.requestAnimationFrame) {
            window.requestAnimationFrame(() => {
                import.meta.hot.send('custom:log', {
                    logType: 'network',
                    level: 'ERROR',
                    message: logMessage,
                    meta: {
                        timestamp: Date.now()
                    }
                });
            });
        }
    });

    // --- UNHANDLED PROMISE REJECTION HANDLING ---
    window.addEventListener('unhandledrejection', (event) => {
        const reason = event.reason;
        const message = reason instanceof Error
            ? `${reason.name}: ${reason.message}\n${reason.stack}`
            : String(reason);

        const logMessage = `UNHANDLED_REJECTION: ${message}`;
        log.error(logMessage);

        if (!isProd && import.meta.hot && window.requestAnimationFrame) {
            window.requestAnimationFrame(() => {
                import.meta.hot.send('custom:log', {
                    logType: 'network',
                    level: 'ERROR',
                    message: logMessage,
                    meta: {
                        timestamp: Date.now()
                    }
                });
            });
        }
    });
} catch (error) {
    console.error('Failed to set up network error tracking:', error);
}

// Now it's safe to override console methods
console.log = log.info.bind(log);
console.info = log.info.bind(log);
console.warn = log.warn.bind(log);
console.error = log.error.bind(log);
console.debug = log.debug.bind(log);

export default log;