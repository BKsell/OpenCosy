# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you find a security vulnerability, please open an issue or contact the maintainers.

## Security Hardening

This project has undergone security hardening including:
- Disabled nodeIntegration in all renderer processes
- Enabled contextIsolation and sandbox mode
- Added preload.js with contextBridge for secure IPC
- XSS vulnerability fixes in downloadlist.html and extensions.html
- Path traversal protection in extension management
- URL protocol validation for navigation
- Permission request handler for sensitive APIs
