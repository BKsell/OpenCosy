'use strict';

const RESERVED_NAMES = new Set([
  'con', 'prn', 'aux', 'nul',
  'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
  'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9',
]);

function hasControlChar(value) {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
    if (code >= 0x80 && code <= 0x9f) return true;
  }
  return false;
}

function hasAlternateDataStream(value) {
  let probe = value;
  if (/^[A-Za-z]:/.test(probe)) {
    probe = probe.slice(2);
  }
  return probe.includes(':');
}

function isReservedDeviceName(name) {
  const stem = name.split('.')[0].toLowerCase();
  return RESERVED_NAMES.has(stem);
}

module.exports = { RESERVED_NAMES, hasControlChar, hasAlternateDataStream, isReservedDeviceName };
