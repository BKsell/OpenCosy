'use strict';

// deeplinkguard.js —— 进程入口深链（命令行 argv / open-file / open-url）消毒内核。
//
// 威胁模型：
//   浏览器注册为 cosy: 协议处理器和 .html 文件处理器后，操作系统会把“外部深链”
//   作为参数在启动新进程（process.argv）或单实例激活（macOS open-url / open-file）
//   时送进来。这些输入来自任意其它程序 / 网页（网页可以让系统带着恶意参数拉起
//   默认浏览器），属于不可信数据，而历史代码：
//     1) 直接 `'file://' + arg` 拼本地路径 —— Windows 路径是反斜杠、含空格 / # / ?
//        / %，裸拼出来的 file: URL 语义错误，可被构造指向意料外位置；
//     2) 只按后缀字符串结尾判断，.HTML（大写）与尾随点 / 空格可绕过；
//     3) 不检查控制字符 / CR/LF、不拦 '--' 开头的 Chromium 开关样参数；
//     4) cosy:// 深链不校验主机，任意主机名都被带进新建标签。
//   本模块只做纯判定：输入字符串 → { ok, kind, value, reason }，不调用 Electron /
//   fs，真实“文件是否存在 / 转 file: URL / 开标签”由 main.js 完成。

const path = require('path');

const MAX_DEEPLINK_LENGTH = 4096;

// 允许经深链打开的内部页主机（与 main.js 的 cosy: pageMap 保持一致）。
const DEFAULT_INTERNAL_HOSTS = new Set([
  'setting', 'newtab', 'extensions', 'version', 'sitedata',
  'permissions', 'security', 'hashes', 'download', 'downloadlist',
]);

// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\x00-\x1f\x7f]/;

function hasControlChar(s) {
  return typeof s !== 'string' || CONTROL_RE.test(s);
}

function safeParse(raw) {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

function isSwitchLike(s) {
  // Chromium / Electron 命令行参数以 '-' 开头（--foo / -foo）。深链绝不该长这样，
  // 挡掉可被当作开关注入的参数。
  return typeof s === 'string' && s.length > 0 && s[0] === '-';
}

function basicReject(raw) {
  if (typeof raw !== 'string') return 'not-string';
  if (raw.trim() === '') return 'empty';
  if (raw.length > MAX_DEEPLINK_LENGTH) return 'too-long';
  if (hasControlChar(raw)) return 'control-char';
  if (isSwitchLike(raw.trim())) return 'switch-like';
  return '';
}

// reviewWebUrl 校验 http(s) 深链：必须可解析、有主机、协议正确。
function reviewWebUrl(raw) {
  const reject = basicReject(raw);
  if (reject) return { ok: false, kind: 'web', reason: reject };
  const u = safeParse(raw.trim());
  if (!u) return { ok: false, kind: 'web', reason: 'unparseable' };
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    return { ok: false, kind: 'web', reason: 'scheme' };
  }
  if (!u.hostname) return { ok: false, kind: 'web', reason: 'no-host' };
  return { ok: true, kind: 'web', value: u.href };
}

// reviewInternalUrl 校验 cosy: 深链：主机必须在白名单内。
function reviewInternalUrl(raw, allowedHosts) {
  const reject = basicReject(raw);
  if (reject) return { ok: false, kind: 'internal', reason: reject };
  const u = safeParse(raw.trim());
  if (!u) return { ok: false, kind: 'internal', reason: 'unparseable' };
  if (u.protocol !== 'cosy:') return { ok: false, kind: 'internal', reason: 'scheme' };
  const hosts = allowedHosts instanceof Set
    ? allowedHosts
    : Array.isArray(allowedHosts) ? new Set(allowedHosts) : DEFAULT_INTERNAL_HOSTS;
  const host = (u.hostname || '').toLowerCase();
  if (!hosts.has(host)) return { ok: false, kind: 'internal', reason: 'host' };
  return { ok: true, kind: 'internal', value: u.href, host };
}

// isAbsoluteInput 跨平台判断是否为绝对路径（Windows 盘符或 UNC，POSIX 根）。
function isAbsoluteInput(p) {
  if (path.isAbsolute(p)) return true;
  // path.isAbsolute 在 win32 上认 'C:\' 与 '\\';这里再兜底盘符。
  return /^[a-zA-Z]:[\\/]/.test(p) || /^\\\\/.test(p);
}

// HTML_EXT 大小写不敏感后缀判断，去掉尾随点 / 空格后再判（Windows 会忽略尾点）。
function isHtmlFile(p) {
  const base = path.basename(p).replace(/[. ]+$/g, '').toLowerCase();
  return base.endsWith('.html') || base.endsWith('.htm');
}

// reviewLocalHtml 校验经“打开文件”进来的本地 HTML：
//   必须是绝对路径、后缀为 .html/.htm、非 UNC、归一化后不含穿越片段。
// 返回 value 为 path.resolve 后的绝对路径（调用方负责 existsSync 与转 file: URL）。
function reviewLocalHtml(rawPath) {
  const reject = basicReject(rawPath);
  if (reject) return { ok: false, kind: 'local-html', reason: reject };
  const p = rawPath.trim();
  if (/^\\\\/.test(p)) return { ok: false, kind: 'local-html', reason: 'unc' };
  if (!isAbsoluteInput(p)) return { ok: false, kind: 'local-html', reason: 'not-absolute' };
  if (!isHtmlFile(p)) return { ok: false, kind: 'local-html', reason: 'not-html' };
  // 必须在 resolve 之前判 '..'：path.resolve 会把 .. 直接折叠掉，折叠后再查
  // 就发现不了越界了。系统正常下发的是规范化绝对路径，含 '..' 段一律拒。
  const rawSegs = p.split(/[\\/]/);
  if (rawSegs.includes('..')) return { ok: false, kind: 'local-html', reason: 'traversal' };
  const resolved = path.resolve(p);
  if (hasControlChar(resolved)) return { ok: false, kind: 'local-html', reason: 'control-char' };
  return { ok: true, kind: 'local-html', value: resolved };
}

// reviewStartupArg 按前缀 / 后缀把一条入口参数分到三类之一并校验。
// 显式协议前缀优先（http(s)://、cosy://）；否则当本地 HTML 路径处理。
function reviewStartupArg(raw, allowedHosts) {
  const reject = basicReject(raw);
  if (reject) return { ok: false, kind: 'unknown', reason: reject };
  const s = raw.trim();
  if (/^https:\/\//i.test(s) || /^http:\/\//i.test(s)) return reviewWebUrl(s);
  if (/^cosy:\/\//i.test(s)) return reviewInternalUrl(s, allowedHosts);
  // Windows 盘符（C:\ / C:/）或 UNC 是本地路径，必须在通用“协议”正则之前识别，
  // 否则盘符 'C:' 会被误判成自定义协议。
  if (/^[a-zA-Z]:[\\/]/.test(s) || /^\\\\/.test(s)) return reviewLocalHtml(s);
  // 其它协议（file:/javascript:/外部协议等）不作为启动深链接受。
  if (/^[a-zA-Z][a-zA-Z0-9+.-]{0,31}:/.test(s)) {
    return { ok: false, kind: 'unknown', reason: 'scheme' };
  }
  return reviewLocalHtml(s);
}

// MAX_ARGV_SCAN 限制我们愿意扫描的命令行参数数量，防止异常超长 argv 拖垮启动。
const MAX_ARGV_SCAN = 64;

// pickDeepLinkFromArgv 从 process.argv 形态的数组里找出第一个合法深链。
// Windows 下协议处理器拉起浏览器时，深链在参数中的位置并不固定（可能伴随
// Chromium 自己的开关、可能不在 argv[1]），因此不能写死取 argv[1]。
// 规则：跳过 '-' 开头的开关及其可能的取值（保守起见只跳过开关本身）、跳过
// 可执行文件路径本身（argv[0]），逐条交给 reviewStartupArg，返回首个通过者。
function pickDeepLinkFromArgv(argv, allowedHosts) {
  if (!Array.isArray(argv)) return null;
  const end = Math.min(argv.length, MAX_ARGV_SCAN + 1);
  for (let i = 1; i < end; i++) {
    const raw = argv[i];
    if (typeof raw !== 'string' || raw === '') continue;
    if (isSwitchLike(raw.trim())) continue;
    const review = reviewStartupArg(raw, allowedHosts);
    if (review.ok) return review;
    // 非开关但不合法的参数：继续找下一个（例如 argv 里混着无意义的路径片段），
    // 不在这里记审计，由调用方决定是否需要。
  }
  return null;
}

// describeReason 稳定中文说明（不回显完整输入）。
function describeReason(reason) {
  const map = {
    'not-string': '深链不是字符串',
    empty: '深链为空',
    'too-long': '深链过长',
    'control-char': '深链含控制字符',
    'switch-like': '深链形似命令行开关',
    unparseable: '深链无法解析',
    scheme: '不允许的深链协议',
    'no-host': '深链缺少主机名',
    host: '内部深链主机不在白名单',
    unc: '不接受网络共享(UNC)路径',
    'not-absolute': '本地文件必须是绝对路径',
    'not-html': '只接受 .html/.htm 文件',
    traversal: '本地路径含目录穿越',
  };
  return Object.prototype.hasOwnProperty.call(map, reason) ? map[reason] : '不安全的深链';
}

module.exports = {
  reviewStartupArg,
  reviewWebUrl,
  reviewInternalUrl,
  reviewLocalHtml,
  pickDeepLinkFromArgv,
  isHtmlFile,
  isSwitchLike,
  hasControlChar,
  describeReason,
  DEFAULT_INTERNAL_HOSTS,
  MAX_DEEPLINK_LENGTH,
  MAX_ARGV_SCAN,
};
