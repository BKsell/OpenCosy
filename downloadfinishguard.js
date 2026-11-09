'use strict';

const path = require('path');

const ACTION = { OK: 'ok', WARN: 'warn', BLOCK: 'block' };

const REASON = {
  OK: 'ok',
  NO_PATH: 'no-path',
  OUTSIDE_ROOT: 'outside-root',
  SYMLINK: 'symlink',
  NOT_REGULAR: 'not-regular',
  EMPTY_FILE: 'empty-file',
  SHORT_BYTES: 'short-bytes',
  OVERSIZE: 'oversize',
  NAME_MISMATCH: 'name-mismatch',
};

const MAX_SIZE_SLACK_BYTES = 4096;

function isContained(rootDir, targetPath) {
  const root = path.resolve(String(rootDir || ''));
  const target = path.resolve(String(targetPath || ''));
  const relative = path.relative(root, target);
  if (!relative) return true;
  if (path.isAbsolute(relative)) return false;
  return relative.split(path.sep)[0] !== '..';
}

function expectedNameOf(savePath) {
  return path.basename(String(savePath || ''));
}

function auditDownloadResult(input = {}) {
  const rootDir = String(input.rootDir || '');
  const savePath = String(input.savePath || '');
  const expectedName = String(input.expectedName || expectedNameOf(savePath));
  const audit = { action: ACTION.OK, reason: REASON.OK, detail: '', path: savePath };

  if (!savePath) {
    return Object.assign(audit, { action: ACTION.BLOCK, reason: REASON.NO_PATH, detail: '下载完成但没有保存路径' });
  }
  if (!isContained(rootDir, savePath)) {
    return Object.assign(audit, { action: ACTION.BLOCK, reason: REASON.OUTSIDE_ROOT, detail: '落盘路径逃出下载根目录' });
  }
  if (expectedName && expectedNameOf(savePath) !== expectedName) {
    return Object.assign(audit, { action: ACTION.BLOCK, reason: REASON.NAME_MISMATCH, detail: '最终文件名与准入文件名不一致' });
  }
  if (input.isSymlink === true) {
    return Object.assign(audit, { action: ACTION.BLOCK, reason: REASON.SYMLINK, detail: '落盘结果是符号链接' });
  }
  if (input.isRegular === false) {
    return Object.assign(audit, { action: ACTION.BLOCK, reason: REASON.NOT_REGULAR, detail: '落盘结果不是普通文件' });
  }

  const actualBytes = Number(input.actualBytes);
  const expectedBytes = Number(input.expectedBytes);
  if (Number.isFinite(actualBytes) && actualBytes === 0) {
    return Object.assign(audit, { action: ACTION.BLOCK, reason: REASON.EMPTY_FILE, detail: '落盘文件为 0 字节' });
  }
  if (Number.isFinite(actualBytes) && Number.isFinite(expectedBytes) && expectedBytes > 0) {
    const tolerance = Math.min(MAX_SIZE_SLACK_BYTES, Math.max(64, Math.floor(expectedBytes / 10)));
    if (actualBytes < expectedBytes - tolerance) {
      return Object.assign(audit, {
        action: ACTION.BLOCK, reason: REASON.SHORT_BYTES,
        detail: `落盘 ${actualBytes} 字节，少于声明的 ${expectedBytes} 字节`,
      });
    }
    if (actualBytes > expectedBytes + tolerance) {
      return Object.assign(audit, {
        action: ACTION.WARN, reason: REASON.OVERSIZE,
        detail: `落盘 ${actualBytes} 字节，多于声明的 ${expectedBytes} 字节`,
      });
    }
  }
  return audit;
}

function describeDownloadAudit(audit) {
  if (!audit || audit.reason === REASON.OK) return '下载落盘校验通过';
  return `${audit.reason}: ${audit.detail || ''}`.trim();
}

module.exports = {
  ACTION,
  REASON,
  MAX_SIZE_SLACK_BYTES,
  auditDownloadResult,
  describeDownloadAudit,
  isContained,
};
