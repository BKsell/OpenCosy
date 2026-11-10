'use strict';
const { describeReasonFrom } = require('./reasontext');

const { containsControlChar, isExecutableName } = require('./shellguard_check');

const MAX_PATH_LENGTH = 1024;

// reviewLocalLaunchPath 评估交给 openPath / showItemInFolder 的本地路径。
// 调用方需先用 path.resolve 归一化并确认位于允许目录内（contained=true）。
// 这里负责：长度、UNC、可执行扩展名、控制字符、穿越片段。
// options.rejectExecutable=true 时（用于 openPath 直接运行）拒绝 exe/lnk/bat 等。
function reviewLocalLaunchPath(resolvedPath, contained, options) {
  if (typeof resolvedPath !== 'string' || resolvedPath.trim() === '') {
    return { ok: false, reason: 'path-empty' };
  }
  if (resolvedPath.length > MAX_PATH_LENGTH) return { ok: false, reason: 'path-long' };
  if (containsControlChar(resolvedPath)) return { ok: false, reason: 'path-control' };
  // UNC（\\host\share）不允许作为“打开下载项”目标。
  if (resolvedPath.startsWith('\\\\')) return { ok: false, reason: 'path-unc' };
  if (!contained) return { ok: false, reason: 'path-outside' };
  // 归一化后的路径里不应再出现 .. 段。
  const segs = resolvedPath.split(/[\\/]/);
  if (segs.includes('..')) return { ok: false, reason: 'path-traversal' };
  if (options && options.rejectExecutable) {
    const base = segs[segs.length - 1] || '';
    if (isExecutableName(base)) return { ok: false, reason: 'path-executable' };
  }
  return { ok: true };
}

// describeReason 稳定中文说明（不回显完整输入）。
const REASON_TEXT = {
  empty: '外部链接为空',
  'too-long': '外部链接过长',
  'control-char': '外部链接含控制字符',
  'switch-like': '外部链接形似命令开关',
  unparseable: '外部链接无法解析',
  scheme: '不允许的外部协议',
  userinfo: '外部链接携带账号信息',
  'encoded-control': '外部链接含编码控制字符',
  'mailto-too-many': '邮件收件人过多',
  'mailto-addr-long': '邮件地址过长',
  'mailto-bad-addr': '邮件地址格式非法',
  'mailto-bad-local': '邮件账号部分含非法字符',
  'mailto-bad-domain': '邮件域名含非法字符',
  'tel-empty': '电话号码为空',
  'tel-bad-char': '电话号码含非法字符',
  'tel-no-digit': '电话号码没有数字',
  'tel-too-long': '电话号码过长',
  'path-empty': '本地路径为空',
  'path-long': '本地路径过长',
  'path-control': '本地路径含控制字符',
  'path-unc': '不允许打开网络共享路径',
  'path-outside': '本地路径不在允许目录内',
  'path-traversal': '本地路径含目录穿越',
  'path-executable': '不允许直接运行可执行或快捷方式文件',
};

function describeReason(reason) {
  return describeReasonFrom(REASON_TEXT, reason, '不安全的外部唤起');
}
