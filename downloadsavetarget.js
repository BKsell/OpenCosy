'use strict';

const path = require('path');

const MAX_SAVE_NAME_CHARS = 180;
const MAX_SAVE_PATH_CHARS = 1024;

const REASON = {
  OK: 'ok',
  EMPTY_ROOT: 'empty-root',
  EMPTY_TARGET: 'empty-target',
  BAD_PATH: 'bad-path',
  BAD_NAME: 'bad-name',
  OUTSIDE_ROOT: 'outside-root',
  RESERVED_NAME: 'reserved-name',
  BAD_EXTENSION_SHAPE: 'bad-extension-shape',
};

const RESERVED_NAMES = new Set([
  'con', 'prn', 'aux', 'nul',
  'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
  'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9',
]);

function hasControlChar(value) {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
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

function auditSaveName(name) {
  if (typeof name !== 'string' || name.length === 0) return REASON.BAD_NAME;
  if (name.length > MAX_SAVE_NAME_CHARS) return REASON.BAD_NAME;
  if (hasControlChar(name)) return REASON.BAD_NAME;
  if (name.includes('/') || name.includes('\\')) return REASON.BAD_NAME;
  if (name === '.' || name === '..') return REASON.BAD_NAME;
  if (name.endsWith('.') || name.endsWith(' ')) return REASON.BAD_NAME;
  if (hasAlternateDataStream(name)) return REASON.BAD_NAME;
  if (isReservedDeviceName(name)) return REASON.RESERVED_NAME;
  if (name.startsWith('.') && name.length <= 2) return REASON.BAD_NAME;
  return REASON.OK;
}

function auditSaveTarget(rootDir, targetPath, name) {
  if (typeof rootDir !== 'string' || rootDir.trim().length === 0) {
    return { ok: false, reason: REASON.EMPTY_ROOT, path: '', name: '' };
  }
  if (typeof targetPath !== 'string' || targetPath.trim().length === 0) {
    return { ok: false, reason: REASON.EMPTY_TARGET, path: '', name: '' };
  }
  if (targetPath.length > MAX_SAVE_PATH_CHARS || hasControlChar(targetPath)) {
    return { ok: false, reason: REASON.BAD_PATH, path: '', name: '' };
  }
  if (!path.isAbsolute(targetPath)) {
    return { ok: false, reason: REASON.BAD_PATH, path: '', name: '' };
  }
  const fileName = typeof name === 'string' && name.length > 0 ? name : path.basename(targetPath);
  const nameVerdict = auditSaveName(fileName);
  if (nameVerdict !== REASON.OK) {
    return { ok: false, reason: nameVerdict, path: '', name: fileName };
  }
  const rootAbs = path.resolve(rootDir);
  const targetAbs = path.resolve(targetPath);
  const relative = path.relative(rootAbs, targetAbs);
  if (relative.length === 0 || relative.startsWith('..') || path.isAbsolute(relative)) {
    return { ok: false, reason: REASON.OUTSIDE_ROOT, path: targetAbs, name: fileName };
  }
  if (path.basename(targetAbs) !== fileName) {
    return { ok: false, reason: REASON.BAD_PATH, path: targetAbs, name: fileName };
  }
  return { ok: true, reason: REASON.OK, path: targetAbs, name: fileName };
}

function describeSaveTargetReject(reason) {
  switch (reason) {
    case REASON.OK:
      return '保存目标通过校验';
    case REASON.EMPTY_ROOT:
      return '下载保存根目录为空';
    case REASON.EMPTY_TARGET:
      return '下载保存路径为空';
    case REASON.BAD_PATH:
      return '下载保存路径不是合法的绝对路径';
    case REASON.BAD_NAME:
      return '下载文件名包含非法字符或结构';
    case REASON.OUTSIDE_ROOT:
      return '下载保存路径越出下载目录';
    case REASON.RESERVED_NAME:
      return '下载文件名是系统保留设备名';
    case REASON.BAD_EXTENSION_SHAPE:
      return '下载文件名扩展名结构异常';
    default:
      return '下载保存目标未通过校验';
  }
}

module.exports = {
  REASON,
  MAX_SAVE_NAME_CHARS,
  MAX_SAVE_PATH_CHARS,
  auditSaveName,
  auditSaveTarget,
  describeSaveTargetReject,
  hasAlternateDataStream,
  isReservedDeviceName,
};
