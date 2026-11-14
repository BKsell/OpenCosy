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


const AREA = {
  IPC_PAYLOAD: 'ipc-payload',
  IPC_REPLY: 'ipc-reply',
  PATH: 'path',
  JSON_IMPORT: 'json-import',
  DOWNLOAD: 'download',
  FILE_MAGIC: 'file-magic',
  CLIPBOARD: 'clipboard',
  SECRET: 'secret',
  REDIRECT: 'redirect',
  PROXY: 'proxy',
  SRI: 'sri',
  UPDATE: 'update',
  CSP: 'csp',
  MIME: 'mime',
  ARCHIVE: 'archive',
  CSV: 'csv',
  COOKIE: 'cookie',
  ENCODING: 'encoding',
  SVG: 'svg',
  PDF: 'pdf',
  HTML_TEXT: 'html-text',
};

const CHAIN_AREAS = Object.values(AREA);

function finding(area, result) {
  return {
    area,
    changed: result.changed === true,
    reason: result.reason,
    detail: typeof result.reason === 'string' ? result.reason : '',
  };
}

function inspectIpcRequest(args) {
  const values = Array.isArray(args) ? args : [args];
  const findings = [];
  for (let i = 0; i < values.length; i += 1) {
    findings.push(finding(AREA.IPC_PAYLOAD, ipcPayload.applyIpcPayloadGuard(values[i])));
  }
  return { changed: findings.some((item) => item.changed), findings };
}

function inspectIpcReply(value) {
  return finding(AREA.IPC_REPLY, ipcReply.applyReplyGuard(value));
}

function inspectPathWithin(baseDir, target) {
  return finding(AREA.PATH, pathContainment.applyPathContainmentGuard(baseDir, target));
}

function inspectImportJson(text) {
  return finding(AREA.JSON_IMPORT, jsonImport.applyImportPayloadGuard(text));
}

function inspectDownloadCandidate(download) {
  return finding(AREA.DOWNLOAD, downloadPolicy.applyDownloadPolicyGuard(download));
}

function inspectDownloadedBuffer(buffer, declaredType) {
  return finding(AREA.FILE_MAGIC, fileMagic.applyFileMagicGuard(buffer, declaredType));
}

function sanitizeClipboard(text, limits) {
  return finding(AREA.CLIPBOARD, clipboardText.applyClipboardTextGuard(text, limits));
}

function redactText(text) {
  return finding(AREA.SECRET, secretRedact.applySecretRedactGuard(text));
}

function inspectRedirectHop(hop) {
  return finding(AREA.REDIRECT, redirectCredential.applyRedirectCredentialGuard(hop));
}

function inspectProxySettings(config) {
  return finding(AREA.PROXY, proxyConfig.applyProxyConfigGuard(config));
}

function inspectIntegrity(buffer, integrity) {
  return finding(AREA.SRI, sriHash.applySriGuard(buffer, integrity));
}

function inspectUpdateManifest(manifest) {
  return finding(AREA.UPDATE, updateArtifact.applyUpdateArtifactGuard(manifest));
}

function inspectCspPolicy(csp, nonce) {
  return finding(AREA.CSP, cspNonce.applyCspNonceGuard(csp, nonce));
}

function inspectContentTypeHeader(value, options) {
  return finding(AREA.MIME, mimeType.applyMimeTypePolicyGuard(value, options));
}

function inspectArchiveEntries(entries, meta) {
  return finding(AREA.ARCHIVE, archiveEntry.applyArchiveEntryGuard(entries, meta));
}

function sanitizeCsvRows(rows) {
  const result = csvFormula.applyCsvFormulaGuard(rows);
  return { area: AREA.CSV, changed: result.changed, reason: result.reason, detail: result.reason };
}


module.exports = {
  AREA,
  CHAIN_AREAS,
  finding,
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
};
