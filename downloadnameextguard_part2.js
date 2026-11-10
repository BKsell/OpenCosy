'use strict';
const { describeReasonFrom } = require('./reasontext');

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

const RESERVED_DEVICE_NAMES = new Set([
  'con', 'prn', 'aux', 'nul',
  'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
  'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9',
]);

const MAX_NAME_LENGTH = 200;

const REASON_TEXT = {
  [REASON.ok]: 'download name acceptable',
  [REASON.doubleExtension]: 'executable hidden behind a decoy extension',
  [REASON.bidiOverride]: 'name carries a bidi override',
  [REASON.controlChars]: 'name carries control characters',
  [REASON.trailingDotSpace]: 'name ends with dots or spaces',
  [REASON.reservedDevice]: 'name maps to a reserved device',
  [REASON.hiddenFile]: 'name resolves to a hidden file',
  [REASON.tooLong]: 'name exceeds the length budget',
  [REASON.malformed]: 'Content-Disposition cannot be parsed',
};

function describeReason(reason) {
  return describeReasonFrom(REASON_TEXT, reason, 'unknown download name verdict');
}

module.exports = { describeReason };
