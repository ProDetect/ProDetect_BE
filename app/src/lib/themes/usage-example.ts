/**
 * Theme System Usage Examples
 * --------------------------
 * This file demonstrates how to use the theme system programmatically.
 * It's meant as a reference and isn't executed directly.
 */

import { setTheme, setColorMode, getCurrentTheme, getCurrentColorMode } from "./index";
import { 
  availableThemes, 
  defaultTheme, 
  purpleTheme, 
  blueTheme, 
  greenTheme, 
  redTheme 
} from "@/lib/theme-config";

// Example 1: Setting a theme by name
export function applyBlueTheme() {
  setTheme("blue");
}

// Example 2: Setting a theme using theme object directly
export function applyGreenTheme() {
  // Import the theme object and apply it directly
  import("@/lib/theme-config").then(({ greenTheme, applyTheme }) => {
    const isDarkMode = document.documentElement.classList.contains("dark");
    applyTheme(greenTheme, isDarkMode);
  });
}

// Example 3: Toggle between light and dark mode
export function toggleDarkMode() {
  const currentMode = getCurrentColorMode();
  if (currentMode === "dark") {
    setColorMode("light");
  } else {
    setColorMode("dark");
  }
}

// Example 4: Set to system theme preference
export function useSystemTheme() {
  setColorMode("system");
}

// Example 5: Create and apply a custom theme
export function applyCustomTheme() {
  // Custom theme that follows the ThemeConfig structure
  const customTheme = {
    name: "custom",
    light: {
      "--radius": "0.625rem",
      "--radius-sm": "calc(var(--radius) - 4px)",
      "--radius-md": "calc(var(--radius) - 2px)",
      "--radius-lg": "var(--radius)",
      "--radius-xl": "calc(var(--radius) + 4px)",
      
      "--background": "oklch(0.98 0.01 90)",
      "--foreground": "oklch(0.2 0.02 240)",
      "--card": "oklch(1 0 0)",
      "--card-foreground": "oklch(0.2 0.02 240)",
      "--popover": "oklch(1 0 0)",
      "--popover-foreground": "oklch(0.2 0.02 240)",
      "--primary": "oklch(0.6 0.25 180)",
      "--primary-foreground": "oklch(0.985 0 0)",
      "--secondary": "oklch(0.95 0.03 190)",
      "--secondary-foreground": "oklch(0.2 0.02 240)",
      "--muted": "oklch(0.95 0.03 190)",
      "--muted-foreground": "oklch(0.5 0.05 240)",
      "--accent": "oklch(0.95 0.03 190)",
      "--accent-foreground": "oklch(0.2 0.02 240)",
      "--destructive": "oklch(0.6 0.25 30)",
      "--destructive-foreground": "oklch(0.985 0 0)",
      "--border": "oklch(0.9 0.02 240)",
      "--input": "oklch(0.9 0.02 240)",
      "--ring": "oklch(0.6 0.25 180)",
      
      // Also support sidebar variables
      "--sidebar": "oklch(0.97 0.02 190)",
      "--sidebar-foreground": "oklch(0.2 0.02 240)",
      "--sidebar-primary": "oklch(0.6 0.25 180)",
      "--sidebar-primary-foreground": "oklch(0.985 0 0)",
      "--sidebar-accent": "oklch(0.95 0.03 190)",
      "--sidebar-accent-foreground": "oklch(0.2 0.02 240)",
      "--sidebar-border": "oklch(0.9 0.02 240)",
      "--sidebar-ring": "oklch(0.6 0.25 180)",
      
      // Chart colors
      "--chart-1": "oklch(0.6 0.25 180)",
      "--chart-2": "oklch(0.6 0.25 140)",
      "--chart-3": "oklch(0.6 0.25 100)",
      "--chart-4": "oklch(0.6 0.25 60)",
      "--chart-5": "oklch(0.6 0.25 20)",
    },
    dark: {
      "--radius": "0.625rem",
      "--radius-sm": "calc(var(--radius) - 4px)",
      "--radius-md": "calc(var(--radius) - 2px)",
      "--radius-lg": "var(--radius)",
      "--radius-xl": "calc(var(--radius) + 4px)",
      
      "--background": "oklch(0.15 0.02 260)",
      "--foreground": "oklch(0.95 0 0)",
      "--card": "oklch(0.2 0.02 260)",
      "--card-foreground": "oklch(0.95 0 0)",
      "--popover": "oklch(0.2 0.02 260)",
      "--popover-foreground": "oklch(0.95 0 0)",
      "--primary": "oklch(0.65 0.3 190)",
      "--primary-foreground": "oklch(0.2 0.02 260)",
      "--secondary": "oklch(0.3 0.05 260)",
      "--secondary-foreground": "oklch(0.95 0 0)",
      "--muted": "oklch(0.3 0.05 260)",
      "--muted-foreground": "oklch(0.7 0.05 260)",
      "--accent": "oklch(0.3 0.05 260)",
      "--accent-foreground": "oklch(0.95 0 0)",
      "--destructive": "oklch(0.6 0.3 30)",
      "--destructive-foreground": "oklch(0.95 0 0)",
      "--border": "oklch(0.3 0.05 260)",
      "--input": "oklch(0.3 0.05 260)",
      "--ring": "oklch(0.65 0.3 190)",
      
      // Also support sidebar variables
      "--sidebar": "oklch(0.2 0.04 260)",
      "--sidebar-foreground": "oklch(0.95 0 0)",
      "--sidebar-primary": "oklch(0.65 0.3 190)",
      "--sidebar-primary-foreground": "oklch(0.2 0.02 260)",
      "--sidebar-accent": "oklch(0.3 0.05 260)",
      "--sidebar-accent-foreground": "oklch(0.95 0 0)",
      "--sidebar-border": "oklch(0.4 0.05 260)",
      "--sidebar-ring": "oklch(0.65 0.3 190)",
      
      // Chart colors
      "--chart-1": "oklch(0.65 0.3 190)",
      "--chart-2": "oklch(0.65 0.3 150)",
      "--chart-3": "oklch(0.65 0.3 110)",
      "--chart-4": "oklch(0.65 0.3 70)",
      "--chart-5": "oklch(0.65 0.3 30)",
    }
  };
  
  import("@/lib/theme-config").then(({ applyTheme }) => {
    const isDarkMode = document.documentElement.classList.contains("dark");
    applyTheme(customTheme, isDarkMode);
  });
}

// Example 6: Theme configuration at app startup
export function configureAppTheme() {
  // This code would go in main.tsx or a bootstrap file
  import("@/lib/themes").then(({ initializeTheme }) => {
    initializeTheme({
      theme: "blue", // Default theme name 
      mode: "system", // Use system preferences for light/dark
      autoInitialize: true // Apply immediately
    });
  });
}