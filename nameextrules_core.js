"use strict";

const { RESERVED_DEVICE } = require('./downloadnamesanitize_core');

const REASON = {
  ok: 'ok',
  doubleExtension: 'double-extension',
  bidiOverride: 'bidi-override',
  controlChars: 'control-chars',
  trailingDotSpace: 'trailing-dot-space',
  reservedDevice: 'reserved-device-name',
  hiddenFile: 'hidden-executable',
  tooLong: 'name-too-long',
  malformed: 'malformed-disposition',
};

const EXECUTABLE_EXTENSIONS = new Set([
  'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'msi', 'msp', 'cpl', 'hta',
  'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'ps1', 'ps2', 'jar', 'lnk', 'reg', 'dll',
]);

const DECOY_EXTENSIONS = new Set([
  'pdf', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'txt', 'rtf', 'csv',
  'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar', '7z',
  'mp3', 'mp4', 'avi', 'mkv', 'mov', 'wav', 'flac',
]);

const RESERVED_DEVICE_NAMES = new Set([...RESERVED_DEVICE].map((n) => n.toLowerCase()));

const MAX_NAME_LENGTH = 200;

function hasBidiOverride(text) {
  return /[\u202a-\u202e\u2066-\u2069]/.test(String(text || ''));
}

function hasControlChars(text) {
  return /[\u0000-\u001f\u007f]/.test(String(text || ''));
}

function extensionOf(name) {
  const idx = name.lastIndexOf('.');
  if (idx <= 0 || idx === name.length - 1) return '';
  return name.slice(idx + 1).toLowerCase();
}

function baseNameOf(name) {
  const idx = name.lastIndexOf('.');
  if (idx <= 0) return name;
  return name.slice(0, idx);
}

module.exports = { REASON, EXECUTABLE_EXTENSIONS, DECOY_EXTENSIONS, RESERVED_DEVICE_NAMES, MAX_NAME_LENGTH, hasBidiOverride, hasControlChars, extensionOf, baseNameOf };
