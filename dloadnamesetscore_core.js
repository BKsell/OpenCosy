"use strict";

const EXECUTABLE_EXTS = Object.freeze(new Set([
  'exe', 'scr', 'com', 'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse',
  'ws', 'wsf', 'wsh', 'msi', 'msp', 'mst', 'reg', 'cpl', 'msc', 'lnk', 'url',
  'jar', 'app', 'sh', 'bash', 'run', 'bin', 'deb', 'rpm', 'apk', 'ipa', 'dmg',
  'hta', 'csh', 'ksh', 'desktop', 'action', 'workflow', 'gadget', 'ps2xml',
]));

// 可被脚本引擎解析、风险接近可执行的扩展名。
const SCRIPT_EXTS = Object.freeze(new Set([
  'ps1xml', 'ps1', 'ps2', 'psc1', 'psc2', 'msh', 'msh1', 'msh2', 'vb', 'vbe',
  'sct', 'shb', 'inf', 'scf',
]));

// 常见“无害面具”扩展名：常被用作最后一个扩展名来伪装。
const MASK_EXTS = Object.freeze(new Set([
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'odt', 'ods',
  'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'svg', 'txt', 'md',
  'mp3', 'wav', 'flac', 'mp4', 'mkv', 'avi', 'mov', 'csv', 'json', 'xml',
]));

// 压缩 / 镜像容器：内部文件不带 MOTW，需要提醒。
const CONTAINER_EXTS = Object.freeze(new Set([
  'iso', 'img', 'vhd', 'vhdx', 'vmdk', '7z', 'rar', 'zip', 'gz', 'tar',
  'bz2', 'xz', 'cab', 'wim',
]));

// 以 file:// 打开会获得本地来源、可运行脚本的类型。
const LOCAL_HTML_EXTS = Object.freeze(new Set(['html', 'htm', 'xhtml', 'svg', 'mhtml', 'hta']));

// Windows 保留设备名（不分大小写）。
const RESERVED_BASENAMES = Object.freeze(new Set([
  'con', 'prn', 'aux', 'nul',
  'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
  'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9',
]));

// 危险的不可见 / 格式控制字符。
// 旧集合只覆盖 U+202E/U+202D/U+202C/U+200E/U+200F，漏掉同样能重排显示方向的
// U+202A LRE / U+202B RLE、U+061C 阿拉伯字母标记，以及 U+2066..U+2069 一整套
// 方向隔离符（LRI / RLI / FSI / PDI）——攻击者换个控制符就能让同一个名字的
// 显示顺序完全不同，而旧实现判定为“无风险、直接放行”。
const RTL_OVERRIDE_CHARS = Object.freeze([
  '\u202A', '\u202B', '\u202C', '\u202D', '\u202E',
  '\u200E', '\u200F', '\u061C',
  '\u2066', '\u2067', '\u2068', '\u2069',
]);
// 零宽 / 不可见字符：旧集合只有 U+200B..U+200D 与 U+FEFF，漏了软连字符
// U+00AD、蒙古文元音分隔符 U+180E、词连接符 U+2060 与不可见运算符 U+2061..U+2064。
const ZERO_WIDTH_CHARS = Object.freeze([
  '\u200B', '\u200C', '\u200D', '\uFEFF',
  '\u00AD', '\u180E', '\u2060', '\u2061', '\u2062', '\u2063', '\u2064',
]);

// 可执行内容的 MIME 前缀 / 精确值（小写）。
const EXECUTABLE_MIMES = Object.freeze(new Set([
  'application/x-msdownload',
  'application/x-msdos-program',
  'application/x-dos_msi',
  'application/x-msi',
  'application/x-sh',
  'application/x-shellscript',
  'application/vnd.microsoft.portable-executable',
  'application/x-apple-diskimage',
  'application/java-archive',
  'application/x-executable',
]));
function lower(s) {
  return String(s == null ? '' : s).toLowerCase();
}

// 去掉目录分隔符，只留文件名部分（下载名理论上不含路径，稳妥起见再剥一次）。
function baseNameOnly(filename) {
  const s = String(filename == null ? '' : filename);
  const parts = s.split(/[\\/]/);
  return parts[parts.length - 1] || '';
}

// extname 的纯实现：返回小写扩展名（不含点），无扩展名返回 ''。
function finalExtOf(name) {
  const base = baseNameOnly(name);
  const dot = base.lastIndexOf('.');
  if (dot <= 0 || dot === base.length - 1) {
    return '';
  }
  return lower(base.slice(dot + 1));
}

// 解析整条扩展名链：'invoice.exe.pdf' -> ['exe','pdf']；同时返回词干。
function extensionChain(filename) {
  const base = baseNameOnly(filename);
  const dot = base.indexOf('.');
  if (dot < 0) {
    return { stem: base, chain: [] };
  }
  const stem = base.slice(0, dot);
  const chain = base.slice(dot + 1)
    .split('.')
    .map(seg => lower(seg))
    .filter(seg => seg.length > 0);
  return { stem, chain };
}
function containsAny(s, chars) {
  for (const c of chars) {
    if (s.indexOf(c) >= 0) {
      return c;
    }
  }
  return null;
}
function hasControlChar(s) {
  // 排除常见的 \t，其余 C0 控制符都视为异常。
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 0x20 && s[i] !== '\t') {
      return true;
    }
    if (code === 0x7F) {
      return true;
    }
  }
  return false;
}
function reservedBaseName(stem) {
  // 保留名匹配到第一个 '.' 之前即可（CON.txt 也算）。
  const head = lower(stem).split('.')[0].trim();
  return RESERVED_BASENAMES.has(head);
}

// originalReservedName 在净化/加前缀之前，仅剥离不可见与控制字符后判断原名
// 是否命中 Windows 保留设备名。
function originalReservedName(filename) {
  let s = baseNameOnly(filename);
  for (const c of RTL_OVERRIDE_CHARS) {
    s = s.split(c).join('');
  }
  for (const c of ZERO_WIDTH_CHARS) {
    s = s.split(c).join('');
  }
  s = s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').replace(/[ .]+$/g, '');
  const stem = extensionChain(s).stem;
  return reservedBaseName(stem);
}

// sanitizeName 产出适合真正落盘的名字：剥离路径组件、RTL/零宽/控制字符、
// 结尾点号空格，保留正常的多扩展名（伪装判定交给 analyze，不擅自删扩展名）。
// 返回 { name, changed, rejected }。

module.exports = { EXECUTABLE_EXTS, SCRIPT_EXTS, MASK_EXTS, CONTAINER_EXTS, LOCAL_HTML_EXTS, RESERVED_BASENAMES, RTL_OVERRIDE_CHARS, ZERO_WIDTH_CHARS, EXECUTABLE_MIMES, lower, baseNameOnly, finalExtOf, extensionChain, containsAny, hasControlChar, reservedBaseName, originalReservedName };
