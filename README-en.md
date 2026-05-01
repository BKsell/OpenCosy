# OpenCosy Browser

## Project Overview

OpenCosy Browser is an **open source project** developed by Hot Land Studio (热土工作室) based on [Cosy Browser](https://cosy.rtstu.com).

Cosy Browser is a simple, fast multi-tab browser that provides users with a comfortable browsing experience. The OpenCosy project continues this philosophy, committed to providing users with a lightweight, efficient, and secure open-source browser solution.

## Key Features

- **Multi-tab Browsing**: Support for opening multiple web pages simultaneously with convenient tab management
- **Clean Interface**: Fresh and clean interface design for a comfortable visual experience
- **Fast Response**: Based on Chromium kernel for smooth web page loading
- **Personalized Settings**: Customizable theme colors and search engine configuration
- **Download Management**: Built-in download management for easy file management
- **Extension Support**: Plugin extension support (experimental)

## Technical Architecture

- **Framework**: Electron
- **Kernel**: Chromium
- **Languages**: JavaScript, HTML, CSS

## Version Information

- Current Version: 1.0.0
- License: Apache 2.0

## Getting Started

### Installation

1. Download the latest release
2. Run the installer or execute the portable file
3. Start using OpenCosy Browser

Note:
- This project removes many private features developed by Hot Land Studio. If you want to customize the browser, please use Cosy Browser instead.

### Building from Source

```bash
# Clone the repository
git clone <repository-url>

# Install dependencies
npm install

# Run in development mode
npm run dev

# Build for production
npm run build:win
```

## Project Structure

```
OpenCosy/
├── main.js          # Electron main process
├── package.json     # Project configuration
├── src/             # Frontend source code
│   ├── index.html   # Main page
│   ├── newtab.html  # New tab page
│   ├── settings.html # Settings page
│   └── ...
└── dist/            # Build output directory
```

## Development

### Run Development Mode

```bash
npm run dev
```

### Build Windows Installer

```bash
npm run build:win
```

## About Hot Land Studio

Hot Land Studio (热土工作室) is a team focused on desktop application development, committed to creating quality product experiences for users.

- Official Website: https://cosy.rtstu.com

## License

This project is open source under the Apache 2.0 license.

## Disclaimer

OpenCosy Browser is an open source project developed by Hot Land Studio based on Cosy Browser. Cosy Browser and related names and logos are owned by Hot Land Studio.

This project is for learning and communication purposes only.
