/**
 * Theme API for code-based theme configuration
 * 
 * This module exports functions to programmatically apply themes without requiring UI components.
 * Import themes from theme-config.ts and use these functions to apply them directly in code.
 */

import { applyTheme, getThemeByName, type ThemeConfig } from "@/lib/theme-config";

// Types for theme system
export type ColorMode = "light" | "dark" | "system";

// Function to set the color mode (light/dark/system)
export function setColorMode(mode: ColorMode): void {
  const root = document.documentElement;
  const theme = getThemeByName(getCurrentTheme());
  
  if (!theme) return;
  
  localStorage.setItem("theme-mode", mode);
  
  if (mode === "system") {
    const isDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(theme, isDark);
  } else {
    applyTheme(theme, mode === "dark");
  }
}

// Function to set a specific theme by name
export function setTheme(themeName: string): void {
  const theme = getThemeByName(themeName);
  if (!theme) {
    console.warn(`Theme "${themeName}" not found. Using default theme.`);
    return;
  }
  
  const mode = getCurrentColorMode();
  const isDark = mode === "system" 
    ? window.matchMedia("(prefers-color-scheme: dark)").matches 
    : mode === "dark";
  
  localStorage.setItem("theme-name", themeName);
  applyTheme(theme, isDark);
}

// Function to set a specific theme by theme object
export function setThemeFromConfig(themeConfig: ThemeConfig): void {
  const mode = getCurrentColorMode();
  const isDark = mode === "system" 
    ? window.matchMedia("(prefers-color-scheme: dark)").matches 
    : mode === "dark";
  
  localStorage.setItem("theme-name", themeConfig.name);
  applyTheme(themeConfig, isDark);
}

// Function to get the current color mode
export function getCurrentColorMode(): ColorMode {
  return (localStorage.getItem("theme-mode") as ColorMode) || "system";
}

// Function to get the current theme name
export function getCurrentTheme(): string {
  return localStorage.getItem("theme-name") || "default";
}

// Set up listener for system theme changes
export function initializeThemeSystem(): void {
  // Set up initial theme based on stored preferences
  const storedMode = getCurrentColorMode();
  const storedTheme = getCurrentTheme();
  
  const theme = getThemeByName(storedTheme);
  if (!theme) return;
  
  if (storedMode === "system") {
    const isDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(theme, isDark);
    
    // Add listener for system theme changes
    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
    mediaQuery.addEventListener("change", (e) => {
      const currentTheme = getThemeByName(getCurrentTheme());
      if (currentTheme && getCurrentColorMode() === "system") {
        applyTheme(currentTheme, e.matches);
      }
    });
  } else {
    applyTheme(theme, storedMode === "dark");
  }
}

// Initialize on import if needed
export function initializeTheme(options: { 
  theme?: string; 
  mode?: ColorMode;
  autoInitialize?: boolean;
} = {}): void {
  const { 
    theme = "default", 
    mode = "system",
    autoInitialize = true
  } = options;
  
  if (autoInitialize) {
    // Set initial theme values in localStorage if not present
    if (!localStorage.getItem("theme-mode")) {
      localStorage.setItem("theme-mode", mode);
    }
    
    if (!localStorage.getItem("theme-name")) {
      localStorage.setItem("theme-name", theme);
    }
    
    // Initialize the theme system
    initializeThemeSystem();
  } else {
    // Force update with the provided values
    localStorage.setItem("theme-mode", mode);
    localStorage.setItem("theme-name", theme);
    
    const themeConfig = getThemeByName(theme);
    if (themeConfig) {
      const isDark = mode === "system" 
        ? window.matchMedia("(prefers-color-scheme: dark)").matches 
        : mode === "dark";
      
      applyTheme(themeConfig, isDark);
    }
  }
}