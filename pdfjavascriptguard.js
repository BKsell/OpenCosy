'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  NOT_BUFFER: 'not-buffer',
  NOT_PDF: 'not-pdf',
  TOO_LARGE: 'too-large',
  JAVASCRIPT: 'javascript-action',
  LAUNCH: 'launch-action',
  EMBEDDED_FILE: 'embedded-file',
  OPEN_ACTION: 'open-action',
  RICH_MEDIA: 'rich-media',
  ENCRYPTED: 'encrypted-document',
};

const MAX_BYTES = 32 * 1024 * 1024;
const MARKERS = [
  { token: '/JavaScript', reason: REASON.JAVASCRIPT },
  { token: '/JS', reason: REASON.JAVASCRIPT },
  { token: '/Launch', reason: REASON.LAUNCH },
  { token: '/EmbeddedFile', reason: REASON.EMBEDDED_FILE },
  { token: '/OpenAction', reason: REASON.OPEN_ACTION },
  { token: '/RichMedia', reason: REASON.RICH_MEDIA },
];

function inspectPdf(buffer) {
  if (!Buffer.isBuffer(buffer)) return { ok: false, reason: REASON.NOT_BUFFER, markers: [] };
  if (buffer.length === 0) return { ok: false, reason: REASON.EMPTY, markers: [] };
  if (buffer.length > MAX_BYTES) return { ok: false, reason: REASON.TOO_LARGE, markers: [] };
  const head = buffer.slice(0, 1024).toString('latin1');
  if (!head.includes('%PDF-')) return { ok: false, reason: REASON.NOT_PDF, markers: [] };
  const text = buffer.toString('latin1');
  const markers = [];
  for (const marker of MARKERS) {
    if (text.includes(marker.token)) markers.push(marker.reason);
  }
  if (text.includes('/Encrypt')) markers.push(REASON.ENCRYPTED);
  if (markers.length === 0) return { ok: true, reason: REASON.OK, markers: [] };
  return { ok: false, reason: markers[0], markers };
}

function applyPdfJavaScriptGuard(buffer) {
  const result = inspectPdf(buffer);
  return { changed: !result.ok, reason: result.reason, markers: result.markers };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.EMPTY:
      return 'PDF 内容为空';
    case REASON.NOT_BUFFER:
      return '待检查内容不是二进制缓冲';
    case REASON.NOT_PDF:
      return '内容缺少 PDF 文件头';
    case REASON.TOO_LARGE:
      return 'PDF 超过体积上限';
    case REASON.JAVASCRIPT:
      return 'PDF 含 JavaScript 动作';
    case REASON.LAUNCH:
      return 'PDF 含外部程序启动动作';
    case REASON.EMBEDDED_FILE:
      return 'PDF 含内嵌附件';
    case REASON.OPEN_ACTION:
      return 'PDF 打开即触发动作';
    case REASON.RICH_MEDIA:
      return 'PDF 含富媒体嵌入';
    case REASON.ENCRYPTED:
      return 'PDF 已加密';
    default:
      return 'PDF 未包含主动内容';
  }
}

module.exports = {
  REASON,
  MAX_BYTES,
  MARKERS,
  inspectPdf,
  applyPdfJavaScriptGuard,
  describeReason,
};
