# Tailwind CSS Configuration

This folder contains the Tailwind CSS build configuration for the Hexbon decryption tool.

## Structure

- `package.json` - NPM package configuration with Tailwind CSS v4.1.17 dependencies
- `input.css` - Source CSS file with Tailwind directives
- `node_modules/` - NPM dependencies (git ignored)

## Building CSS

### One-time Build
```bash
npm run build:css --prefix config
```

This will generate `style.css` in the root directory.

### Watch Mode (Auto-rebuild on changes)
```bash
npm run watch:css --prefix config
```

## Configuration

The `input.css` file includes:
- `@import "tailwindcss"` - Main Tailwind CSS import
- `@source "../*.html"` - Scans HTML files for used classes
- `@variant dark` - Enables dark mode support with class-based strategy

## Dark Mode

Dark mode is configured using the `class` strategy. The site checks for:
1. `localStorage.getItem('theme')` - User preference
2. `window.matchMedia('(prefers-color-scheme: dark)')` - System preference

To toggle dark mode, the JavaScript adds/removes the `dark` class on `<html>`.
