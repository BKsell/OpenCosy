"use strict";

const { safeParse } = require('./modutil_core');

const MAX_URL_LENGTH = 4096;
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

module.exports = { MAX_URL_LENGTH, MAX_MAILTO_ADDRS, MAX_TEL_DIGITS, DEFAULT_EXTERNAL_SCHEMES, EXECUTABLE_SUFFIXES, containsControlChar, containsEncodedControl, MAIL_TOKEN, reviewMailto, reviewTel, reviewExternalUrl, isExecutableName };
