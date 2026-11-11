const { EXECUTABLE_EXTS, SCRIPT_EXTS, MASK_EXTS, CONTAINER_EXTS, LOCAL_HTML_EXTS, RESERVED_BASENAMES, RTL_OVERRIDE_CHARS, ZERO_WIDTH_CHARS, EXECUTABLE_MIMES, lower, baseNameOnly, finalExtOf, extensionChain, containsAny, hasControlChar, reservedBaseName, originalReservedName } = require('./dloadnamesetscore');
const DECISION = Object.freeze({
  ALLOW: 'allow',     // 无风险，自动保存
  WARN: 'warn',       // 有注意事项，保存但提示（如本地 HTML、容器内 MOTW 提示）
  CONFIRM: 'confirm', // 必须用户显式确认（可执行 / 伪装 / MIME 不符）
  REJECT: 'reject',   // 直接拒绝（无法净化的非法名）
});

// 可直接执行或能启动程序的扩展名 —— 命中需用户显式确认。
module.exports = {
  DECISION,
  EXECUTABLE_EXTS,
  SCRIPT_EXTS,
  MASK_EXTS,
  CONTAINER_EXTS,
  LOCAL_HTML_EXTS,
  RESERVED_BASENAMES,
  RTL_OVERRIDE_CHARS,
  ZERO_WIDTH_CHARS,
  EXECUTABLE_MIMES,
  lower,
  baseNameOnly,
  finalExtOf,
  extensionChain,
  containsAny,
  hasControlChar,
  reservedBaseName,
  originalReservedName,
};