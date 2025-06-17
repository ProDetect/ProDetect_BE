# ShadCN Theme System

This directory contains a comprehensive theme system for the application, allowing programmatic control of themes without requiring UI components.

## Features

- Multiple built-in themes (default, purple, blue, green, red)
- Support for light and dark modes, with system preference detection
- Easy-to-use API for applying themes programmatically
- Full TypeScript support
- OKLCH color format for better color representation
- Persistence of theme preferences in localStorage
- Support for custom themes

## Usage

### Basic Theme Setup

The theme system is automatically initialized in the main application entry point. By default, it will:

1. Use the system's color scheme preference (light/dark)
2. Apply the default theme
3. Set up listeners for system color scheme changes

### Changing Themes Programmatically

```typescript
import { setTheme, setColorMode } from "@/lib/themes";

// Set a specific theme by name
setTheme("blue");

// Change color mode
setColorMode("dark");  // Options: "light", "dark", "system"
```

### Creating Custom Themes

```typescript
import { applyTheme } from "@/lib/theme-config";

const customTheme = {
  name: "custom",
  light: {
    "--background": "oklch(0.98 0.01 90)",
    "--foreground": "oklch(0.2 0.02 240)",
    "--primary": "oklch(0.6 0.25 180)",
    // ... other CSS variables
  },
  dark: {
    "--background": "oklch(0.15 0.02 260)",
    "--foreground": "oklch(0.95 0 0)",
    "--primary": "oklch(0.65 0.3 190)",
    // ... other CSS variables
  }
};

// Apply the custom theme
const isDarkMode = document.documentElement.classList.contains("dark");
applyTheme(customTheme, isDarkMode);
```

### Theme System Initialization

```typescript
import { initializeTheme } from "@/lib/themes";

initializeTheme({
  theme: "blue",         // Default theme name 
  mode: "system",        // Light/dark mode: "light", "dark", "system"
  autoInitialize: true   // Apply immediately
});
```

## Theme Structure

Each theme follows this structure:

```typescript
interface ThemeConfig {
  name: string;
  light: Record<string, string>; // CSS variables for light mode
  dark: Record<string, string>;  // CSS variables for dark mode
}
```

The CSS variables use the OKLCH color format for better color representation and include support for:

- General UI colors (background, foreground, card, etc.)
- Component-specific colors (primary, secondary, accent, etc.)
- Border radius and other design tokens
- Sidebar-specific styling
- Chart colors

## Files

- `theme-config.ts`: Contains theme definitions and core application functions
- `index.ts`: Exports the theme API for easier consumption
- `usage-example.ts`: Demonstrates how to use the theme system
- `README.md`: Documentation of the theme system

## Integration with Tailwind

The theme system is integrated with Tailwind CSS through the `tailwind.config.js` file, which is set up to use the CSS variables defined in the themes.