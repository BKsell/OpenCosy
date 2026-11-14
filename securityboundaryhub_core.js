'use strict';

const ipcPayload = require('./ipcpayloadguard_core');
const ipcReply = require('./ipcreplyguard_core');
const pathContainment = require('./pathcontainmentguard_core');
const jsonImport = require('./importpayloadguard_core');
const downloadPolicy = require('./downloadpolicyguard_core');
const fileMagic = require('./filemagicguard_core');
const clipboardText = require('./clipboardtextguard_core');
const secretRedact = require('./secretredactguard_core');
const redirectCredential = require('./redirectcredentialguard_core');
const proxyConfig = require('./proxyconfigguard_core');
const sriHash = require('./srihashguard_core');
const updateArtifact = require('./updateartifactguard_core');
const cspNonce = require('./cspnonceguard_core');
const mimeType = require('./mimetypepolicyguard_core');
const archiveEntry = require('./archiveentryguard_core');
const csvFormula = require('./csvformulaguard_core');
const cookieDomain = require('./cookiedomainguard_core');
const contentEncoding = require('./contentencodingbombguard_core');
const svgScript = require('./svgscriptguard_core');
const pdfJavaScript = require('./pdfjavascriptguard_core');
const htmlInjection = require('./htmlinjectionguard_core');

const { AREA, CHAIN_AREAS, finding, inspectArchiveEntries, inspectContentTypeHeader, inspectCspPolicy, inspectDownloadCandidate, inspectDownloadedBuffer, inspectImportJson, inspectIntegrity, inspectIpcReply, inspectIpcRequest, inspectPathWithin, inspectProxySettings, inspectRedirectHop, inspectUpdateManifest, redactText, sanitizeClipboard, sanitizeCsvRows } = require('./securityboundaryhub_findings');
function inspectSvgDocument(content) {
  return finding(AREA.SVG, svgScript.applySvgScriptGuard(content));
}

function inspectPdfDocument(buffer) {
  return finding(AREA.PDF, pdfJavaScript.applyPdfJavaScriptGuard(buffer));
}

function inspectHtmlText(text, options) {
  return finding(AREA.HTML_TEXT, htmlInjection.applyHtmlInjectionGuard(text, options));
}

function firstHeaderValue(headers, name) {
  if (!headers || typeof headers !== 'object') return undefined;
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === name) return headers[key];
  }
  return undefined;
}

function inspectResponseHeaders(headers, host) {
  const findings = [];
  const setCookie = firstHeaderValue(headers, 'set-cookie');
  const cookies = Array.isArray(setCookie) ? setCookie : (typeof setCookie === 'string' ? [setCookie] : []);
  for (const cookie of cookies) {
    const result = cookieDomain.inspectSetCookie(cookie, host);
    findings.push({
      area: AREA.COOKIE,
      changed: !result.ok,
      reason: result.reason,
      detail: result.reason,
    });
  }
  const encoding = contentEncoding.applyContentEncodingGuard(headers);
  findings.push({ area: AREA.ENCODING, changed: encoding.changed, reason: encoding.reason, detail: encoding.reason });
  const contentType = firstHeaderValue(headers, 'content-type');
  if (typeof contentType === 'string' && contentType) {
    const result = mimeType.applyMimeTypePolicyGuard(contentType, { download: false });
    findings.push({ area: AREA.MIME, changed: result.changed, reason: result.reason, detail: result.reason });
  }
  return { changed: findings.some((item) => item.changed), findings };
}

function describeFinding(item) {
  switch (item.area) {
    case AREA.IPC_PAYLOAD:
      return ipcPayload.describeReason(item.reason);
    case AREA.IPC_REPLY:
      return ipcReply.describeReason(item.reason);
    case AREA.PATH:
      return pathContainment.describeReason(item.reason);
    case AREA.JSON_IMPORT:
      return jsonImport.describeReason(item.reason);
    case AREA.DOWNLOAD:
      return downloadPolicy.describeReason(item.reason);
    case AREA.FILE_MAGIC:
      return fileMagic.describeReason(item.reason);
    case AREA.CLIPBOARD:
      return clipboardText.describeReason(item.reason);
    case AREA.SECRET:
      return secretRedact.describeReason(item.reason);
    case AREA.REDIRECT:
      return redirectCredential.describeReason(item.reason);
    case AREA.PROXY:
      return proxyConfig.describeReason(item.reason);
    case AREA.SRI:
      return sriHash.describeReason(item.reason);
    case AREA.UPDATE:
      return updateArtifact.describeReason(item.reason);
    case AREA.CSP:
      return cspNonce.describeReason(item.reason);
    case AREA.MIME:
      return mimeType.describeReason(item.reason);
    case AREA.ARCHIVE:
      return archiveEntry.describeReason(item.reason);
    case AREA.CSV:
      return csvFormula.describeReason(item.reason);
    case AREA.COOKIE:
      return cookieDomain.describeReason(item.reason);
    case AREA.ENCODING:
      return contentEncoding.describeReason(item.reason);
    case AREA.SVG:
      return svgScript.describeReason(item.reason);
    case AREA.PDF:
      return pdfJavaScript.describeReason(item.reason);
    case AREA.HTML_TEXT:
      return htmlInjection.describeReason(item.reason);
    default:
      return '未知安全检查域';
  }
}

function describeFindings(findings) {
  const text = [];
  for (const item of findings || []) {
    if (!item.changed) continue;
    text.push(item.area + ':' + item.reason + '（' + describeFinding(item) + '）');
  }
  return text.join('；');
}

module.exports = {
  AREA,
  CHAIN_AREAS,
  inspectResponseHeaders,
  inspectIpcRequest,
  inspectIpcReply,
  inspectPathWithin,
  inspectImportJson,
  inspectDownloadCandidate,
  inspectDownloadedBuffer,
  sanitizeClipboard,
  redactText,
  inspectRedirectHop,
  inspectProxySettings,
  inspectIntegrity,
  inspectUpdateManifest,
  inspectCspPolicy,
  inspectContentTypeHeader,
  inspectArchiveEntries,
  sanitizeCsvRows,
  inspectSvgDocument,
  inspectPdfDocument,
  inspectHtmlText,
  describeFinding,
  describeFindings,
};
