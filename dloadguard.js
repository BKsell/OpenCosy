
const { DECISION, EXECUTABLE_EXTS, SCRIPT_EXTS, MASK_EXTS, CONTAINER_EXTS, LOCAL_HTML_EXTS, RESERVED_BASENAMES, RTL_OVERRIDE_CHARS, ZERO_WIDTH_CHARS, EXECUTABLE_MIMES, lower, baseNameOnly, finalExtOf, extensionChain, containsAny, hasControlChar, reservedBaseName, originalReservedName } = require('./dloadnamesets');
'use strict';

// dloadguard.js —— 下载文件名伪装与危险类型判定内核（纯函数，无 Electron / fs 依赖）。
//
// 背景：现代浏览器的下载安全不能只看“最后一个扩展名”。drive-by 下载长期靠下面
// 几类视觉/语义伪装绕过“只判 path.extname”的粗粒度检查：
//
//   1. 双扩展名伪装：发票.pdf.exe 能被抓到，但“发票.exe.pdf”这类“危险扩展名夹在
//      中间、最后挂一个无害扩展名”的命名，配合 Windows 隐藏已知扩展名后，用户
//      看到的可能是“发票.exe”，实际落盘类型却是前面的可执行段；
//   2. RTL 反转字符（U+202E / U+202C）：把 “file.pdf ‮exe.scr” 视觉上翻转成
//      “file.pdf rcs.exe”，诱导用户以为是 PDF；
//   3. 结尾点号 / 空格 / 控制字符：Windows 落盘时会剥掉结尾的 '.' 与空格，
//      “x.exe.” “x.exe ” 在资源管理器里等价于 x.exe；
//   4. Windows 保留设备名：CON / PRN / AUX / NUL / COM1..9 / LPT1..9，命名不当
//      会导致写入失败或落到特殊设备；
//   5. MIME 与扩展名不一致：响应头声明 application/x-msdownload，名字却叫
//      “报表.pdf”，是典型的可执行内容伪装；
//   6. 镜像 / 压缩容器（.iso/.img/.vhd/.7z）：Windows 对容器内部文件不下发
//      Mark-of-the-Web，解压/挂载后的 exe 可绕过 SmartScreen；
//   7. 本地 HTML/SVG：以 file:// 来源打开，可内嵌脚本，脱离站点沙箱与 CSP。
//
// 本内核只负责“分析 + 给出决策与原因”，不弹任何 UI；调用方（main 进程）据此
// 决定自动保存、弹确认还是拒绝，并把结果写入安全台账。

function sanitizeName(filename) {
  let name = baseNameOnly(filename);
  const original = name;

  for (const c of RTL_OVERRIDE_CHARS) {
    name = name.split(c).join('');
  }
  for (const c of ZERO_WIDTH_CHARS) {
    name = name.split(c).join('');
  }
  name = name.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

  // Windows 文件名里不允许 ':'，但裸 ':' 会被 NTFS 当成备用数据流分隔符：
  // "a.txt:hidden.exe" 实际写到 a.txt 的 hidden.exe 流，磁盘上只看得到一个无害的
  // a.txt。旧实现原样放行冒号，这里统一替换成 '_'，保证落盘名与审计名一致。
  name = name.replace(/:/g, '_');

  // Windows 落盘会剥掉结尾的 '.' 与空格，这里先剥，保证审计看到的名字与磁盘一致。
  name = name.replace(/[ .]+$/g, '');

  if (name === '' || name === '.' || name === '..') {
    return { name: '', changed: true, rejected: true };
  }
  const { stem } = extensionChain(name);
  if (reservedBaseName(stem)) {
    // 不直接拒绝，给保留名加前缀让它变成普通文件（Chrome 同思路）。
    name = '_' + name;
  }
  return { name, changed: name !== original, rejected: false };
}

// analyzeMimeMismatch 判断“声明的内容类型”与“最终扩展名”是否矛盾。
// 返回 risk 对象或 null。
function analyzeMimeMismatch(mime, filename) {
  const mt = lower(String(mime || '').split(';')[0].trim());
  if (!mt) {
    return null;
  }
  const isExecMime = EXECUTABLE_MIMES.has(mt) ||
    (mt.startsWith('application/x-ms') && mt !== 'application/x-ms-application');
  if (!isExecMime) {
    return null;
  }
  const finalExt = finalExtOf(filename);
  if (EXECUTABLE_EXTS.has(finalExt) || SCRIPT_EXTS.has(finalExt)) {
    return null; // 扩展名本身已是可执行，交给危险扩展规则，不算“伪装”。
  }
  return {
    id: 'mime-executable-mask',
    severity: DECISION.CONFIRM,
    message: `响应内容类型 ${mt} 是可执行程序，但文件扩展名显示为 .${finalExt || '未知'}，疑似类型伪装`,
  };
}

// analyzeDownloadName 是主入口：给定原始下载文件名与可选 MIME，给出
// { decision, risks, finalExt, chain, displayName }。
function analyzeDownloadName(filename, mime) {
  const risks = [];
  const push = (id, severity, message) => risks.push({ id, severity, message });

  const cleaned = sanitizeName(filename);
  if (cleaned.rejected) {
    return {
      decision: DECISION.REJECT,
      risks: [{ id: 'empty-name', severity: DECISION.REJECT, message: '文件名为空或非法，拒绝保存' }],
      finalExt: '', chain: [], displayName: '',
    };
  }

  const name = cleaned.name;
  const { chain } = extensionChain(name);
  const finalExt = chain.length ? chain[chain.length - 1] : '';
  const isExec = EXECUTABLE_EXTS.has(finalExt) || SCRIPT_EXTS.has(finalExt);
  if (cleaned.changed) {
    push('name-sanitized', DECISION.WARN, '文件名含路径组件、反转/零宽字符或结尾点空格，已在保存前净化');
  }
  if (containsAny(baseNameOnly(filename), RTL_OVERRIDE_CHARS)) {
    push('rtl-override', DECISION.CONFIRM,
      '文件名包含从右到左覆盖字符（U+202E 等），可把扩展名显示成完全不同的样子，属典型伪装手法');
  }
  if (containsAny(baseNameOnly(filename), ZERO_WIDTH_CHARS)) {
    push('zero-width', DECISION.WARN, '文件名包含零宽字符，可能用于视觉混淆');
  }
  if (hasControlChar(baseNameOnly(filename))) {
    push('control-char', DECISION.CONFIRM, '文件名包含控制字符，可能用于绕过类型检查');
  }
  // NTFS 备用数据流：名字里的 ':' 会让内容写进另一个文件的隐藏流，
  // 资源管理器里只显示前半段（a.txt），实际落盘的 exe 完全不可见。
  if (baseNameOnly(filename).indexOf(':') >= 0) {
    push('ntfs-ads', DECISION.CONFIRM,
      '文件名含冒号，Windows 会把它解释成 NTFS 备用数据流（a.txt:hidden.exe 写进 a.txt 的隐藏流），已替换为下划线');
  }
  if (originalReservedName(filename)) {
    push('reserved-name', DECISION.WARN, '文件名命中 Windows 保留设备名（CON/NUL/COM1 等），已自动加前缀');
  }

  // 危险/脚本扩展名：必须确认。
  if (EXECUTABLE_EXTS.has(finalExt)) {
    push('executable-ext', DECISION.CONFIRM, `可执行文件类型 .${finalExt}，运行即获得本机当前用户权限`);
  } else if (SCRIPT_EXTS.has(finalExt)) {
    push('script-ext', DECISION.CONFIRM, `脚本文件类型 .${finalExt}，可被脚本引擎直接执行`);
  }

  // 双扩展名伪装：链中（除最后一段外）出现危险段，最后一段却是无害面具。
  if (chain.length >= 2) {
    const mask = finalExt;
    for (let i = 0; i < chain.length - 1; i++) {
      const seg = chain[i];
      if ((EXECUTABLE_EXTS.has(seg) || SCRIPT_EXTS.has(seg)) &&
          (MASK_EXTS.has(mask) || (!EXECUTABLE_EXTS.has(mask) && !SCRIPT_EXTS.has(mask)))) {
        push('double-extension-spoof', DECISION.CONFIRM,
          `文件名中段含可执行扩展名 .${seg}，末尾却以 .${mask || '?'} 伪装，可能诱导打开`);
        break;
      }
    }
    // 同一可执行扩展名重复出现（x.exe.exe）也很可疑。
    const seen = new Set();
    for (const seg of chain) {
      if (EXECUTABLE_EXTS.has(seg)) {
        if (seen.has(seg)) {
          push('repeated-executable-ext', DECISION.CONFIRM, `可执行扩展名 .${seg} 重复出现，疑似伪装`);
          break;
        }
        seen.add(seg);
      }
    }
  }

  // MIME 与扩展名矛盾。
  const mimeRisk = analyzeMimeMismatch(mime, name);
  if (mimeRisk) {
    risks.push(mimeRisk);
  }

  // 容器：内部文件不继承 MOTW，提醒但不阻断（压缩包是常见需求）。
  if (CONTAINER_EXTS.has(finalExt)) {
    push('container-motw', DECISION.WARN,
      `压缩/镜像容器 .${finalExt} 内部文件不会继承网络来源标记，解压后的程序可能绕过 SmartScreen`);
  }

  // 本地 HTML / SVG：以 file:// 打开即获得本地来源。
  if (LOCAL_HTML_EXTS.has(finalExt) && finalExt !== 'hta') {
    push('local-html', DECISION.WARN,
      `网页/矢量文件 .${finalExt} 下载后以本地来源打开，可执行其中脚本，请勿打开来源不明的此类文件`);
  }

  // 汇总最高决策。
  let decision = DECISION.ALLOW;
  for (const r of risks) {
    if (r.severity === DECISION.REJECT) {
      decision = DECISION.REJECT;
      break;
    }
    if (r.severity === DECISION.CONFIRM) {
      decision = DECISION.CONFIRM;
    } else if (r.severity === DECISION.WARN && decision === DECISION.ALLOW) {
      decision = DECISION.WARN;
    }
  }
  // hta 属于本地 HTML 但本质是可执行 HTML 应用，升级为确认。
  if (finalExt === 'hta' && decision === DECISION.ALLOW) {
    decision = DECISION.CONFIRM;
  }

  return { decision, risks, finalExt, chain, displayName: name, isExecutable: !!isExec };
}

module.exports = {
  DECISION,
  EXECUTABLE_EXTS,
  SCRIPT_EXTS,
  MASK_EXTS,
  CONTAINER_EXTS,
  LOCAL_HTML_EXTS,
  RESERVED_BASENAMES,
  finalExtOf,
  extensionChain,
  sanitizeName,
  analyzeMimeMismatch,
  analyzeDownloadName,
};
