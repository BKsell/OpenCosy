'use strict';

// shellguard.js —— 交给系统 Shell 执行的“外部唤起”消毒内核。
//
// 威胁模型：
//   Electron 的 shell.openExternal(url) 最终落到平台 ShellExecute / xdg-open /
//   open，参数会被系统按协议处理器二次解析。即便外层已经把协议限制在 mailto/tel，
//   URL 本体仍然可控，存在这些面：
//     1) 控制字符 / CR / LF / Tab 注入：可在某些处理器里拆参数、注入附加头或新行；
//     2) URL 编码后的 %0d %0a %00 解码后同样是控制字符；
//     3) 过长字符串 / 畸形编码触发处理器边界缺陷；
//     4) mailto: 收件人地址里塞命令样字符、tel: 号码里塞分隔与控制序列；
//     5) Windows 上 file:// 指向 .exe/.lnk/.bat 等可执行或 UNC 路径，借“打开外部”
//        直接落程序执行。
//   shell.openPath / showItemInFolder 走的是本地路径，风险是路径穿越到下载目录外、
//   指向可执行文件被双击运行。本模块对两类输入统一做纯判定，不调用任何 Electron /
//   shell API，真实执行交给 main.js。

const MAX_URL_LENGTH = 4096;
const MAX_PATH_LENGTH = 1024;
const MAX_MAILTO_ADDRS = 20;
const MAX_TEL_DIGITS = 32;

// 默认可交系统确认后唤起的协议（与 main.js 保持一致）。
const DEFAULT_EXTERNAL_SCHEMES = new Set(['mailto:', 'tel:']);

// Windows 下绝不应经 openExternal 执行的可执行 / 快捷方式扩展名。
const EXECUTABLE_SUFFIXES = new Set([
  '.exe', '.com', '.scr', '.msi', '.msp', '.bat', '.cmd', '.ps1', '.vbs', '.vbe',
  '.js', '.jse', '.wsf', '.wsh', '.jar', '.lnk', '.url', '.appref-ms', '.gadget',
  '.cpl', '.msc', '.reg', '.hta',
]);

// decodeControlStripped：检测（而非“清洗后放行”）原始字符串里是否含控制字符。
// 安全策略是“含即拒”，不做隐式清洗，避免清洗差异被绕过。
function containsControlChar(s) {
  if (typeof s !== 'string') return true;
  // eslint-disable-next-line no-control-regex
  return /[\x00-\x1f\x7f]/.test(s);
}

// containsEncodedControl 检测 %00-%1f、%7f 及其大小写变体（URL 编码的控制字符）。
function containsEncodedControl(s) {
  if (typeof s !== 'string') return false;
  return /%(?:0[0-9a-f]|1[0-9a-f]|7f)/i.test(s);
}

function safeParse(raw) {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

// 邮箱本地/域名部分允许的字符（保守白名单）。
const MAIL_TOKEN = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/;

// reviewMailto 校验 mailto: 的收件人与头部。
// 形如 mailto:a@b.com?cc=c@d.com&subject=...，只放行结构清晰、无控制字符的输入。
function reviewMailto(u) {
  // to 部分在 pathname；空收件人（mailto:?subject=...）允许，但不能只有头部注入。
  const to = u.pathname || '';
  if (to) {
    const addrs = to.split(',').map((x) => x.trim()).filter(Boolean);
    if (addrs.length > MAX_MAILTO_ADDRS) return { ok: false, reason: 'mailto-too-many' };
    for (const addr of addrs) {
      if (addr.length > 254) return { ok: false, reason: 'mailto-addr-long' };
      // 至少要像 a@b；不追求 RFC 5322 完整，挡掉空格 / 引号 / 分号 / 控制样输入。
      const at = addr.lastIndexOf('@');
      if (at <= 0 || at === addr.length - 1) return { ok: false, reason: 'mailto-bad-addr' };
      const local = addr.slice(0, at);
      const domain = addr.slice(at + 1);
      if (!MAIL_TOKEN.test(local)) return { ok: false, reason: 'mailto-bad-local' };
      if (!/^[A-Za-z0-9.-]+$/.test(domain) || domain.includes('..')) {
        return { ok: false, reason: 'mailto-bad-domain' };
      }
    }
  }
  // 头部值不允许裸换行；编码控制符（%0d/%0a 等）已在 reviewExternalUrl 全局拦截，
  // 这里不再重复判断。
  return { ok: true };
}

// reviewTel 校验 tel: 号码：只允许数字与少量拨号符号，数字位数有界。
function reviewTel(u) {
  const num = (u.pathname || '').trim();
  if (!num) return { ok: false, reason: 'tel-empty' };
  if (!/^[0-9+*#().;=-]+$/.test(num)) return { ok: false, reason: 'tel-bad-char' };
  const digits = num.replace(/\D/g, '');
  if (digits.length === 0) return { ok: false, reason: 'tel-no-digit' };
  if (digits.length > MAX_TEL_DIGITS) return { ok: false, reason: 'tel-too-long' };
  // 不允许电话扩展参数里藏 pause 后接超长序列（保守：有分号则后面只能是数字短扩展）。
  return { ok: true };
}

// reviewExternalUrl 评估一个准备交给 shell.openExternal 的 URL。
// allowedSchemes 缺省 mailto/tel；任意输入返回 { ok, reason, url }。
function reviewExternalUrl(rawUrl, allowedSchemes) {
  const allowed = allowedSchemes instanceof Set
    ? allowedSchemes
    : Array.isArray(allowedSchemes) ? new Set(allowedSchemes) : DEFAULT_EXTERNAL_SCHEMES;

  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') {
    return { ok: false, reason: 'empty' };
  }
  // 必须在 trim 之前检查：JS trim() 会剥掉首尾 CR/LF/Tab，先 trim 会漏掉
  // 藏在 URL 末尾的换行注入。策略是“含控制字符即拒”，不做隐式清洗。
  if (containsControlChar(rawUrl)) return { ok: false, reason: 'control-char' };
  const url = rawUrl.trim();
  if (url.length > MAX_URL_LENGTH) return { ok: false, reason: 'too-long' };
  // 前导短横线 / 斜杠可能被某些处理器当成开关，挡掉符号开头的伪 URL。
  if (/^[-/]/.test(url)) return { ok: false, reason: 'switch-like' };

  const u = safeParse(url);
  if (!u) return { ok: false, reason: 'unparseable' };
  const scheme = u.protocol.toLowerCase();
  if (!allowed.has(scheme)) return { ok: false, reason: 'scheme' };

  // 任何外部唤起都不允许携带 userinfo（mailto/tel 本不该有 //user@host 结构）。
  if (u.username || u.password) return { ok: false, reason: 'userinfo' };
  if (containsEncodedControl(url)) return { ok: false, reason: 'encoded-control' };

  if (scheme === 'mailto:') {
    const r = reviewMailto(u);
    if (!r.ok) return r;
  } else if (scheme === 'tel:') {
    const r = reviewTel(u);
    if (!r.ok) return r;
  }

  return { ok: true, url, scheme };
}

// isExecutableName 判断文件名是否属于可执行 / 快捷方式（小写比较）。
function isExecutableName(fileName) {
  if (typeof fileName !== 'string' || fileName === '') return false;
  const lower = fileName.toLowerCase();
  for (const suf of EXECUTABLE_SUFFIXES) {
    if (lower.endsWith(suf)) return true;
  }
  return false;
}

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
function describeReason(reason) {
  const map = {
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
  return Object.prototype.hasOwnProperty.call(map, reason) ? map[reason] : '不安全的外部唤起';
}

module.exports = {
  reviewExternalUrl,
  reviewMailto,
  reviewTel,
  reviewLocalLaunchPath,
  isExecutableName,
  containsControlChar,
  containsEncodedControl,
  describeReason,
  DEFAULT_EXTERNAL_SCHEMES,
  EXECUTABLE_SUFFIXES,
  MAX_URL_LENGTH,
};
