'use strict';

const MAX_PDF_BYTES = 512 * 1024 * 1024;
const PAGE_SIZES = ['A4', 'A3', 'Letter', 'Legal', 'Tabloid'];

function normalizePdfName(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  if (!s || s.length > 200) return null;
  if (s.indexOf('\x00') !== -1 || /[\r\n]/.test(s)) return null;
  const base = s.replace(/\\/g, '/').split('/').pop();
  if (!base || base === '.' || base === '..') return null;
  if (!/\.pdf$/i.test(base)) return null;
  return base;
}

function buildPdfOptions(raw) {
  const p = raw && typeof raw === 'object' ? raw : {};
  const scale = Number(p.scale);
  return {
    pageSize: PAGE_SIZES.indexOf(p.pageSize) === -1 ? 'A4' : p.pageSize,
    landscape: p.landscape === true,
    printBackground: p.printBackground !== false,
    scale: Number.isFinite(scale) && scale >= 0.1 && scale <= 2 ? scale : 1,
    margins: { top: 0.5, bottom: 0.5, left: 0.5, right: 0.5 },
  };
}

function classifyPdfError(err) {
  const code = err && err.code ? String(err.code) : '';
  if (code === 'EACCES' || code === 'EPERM') return 'permission-denied';
  if (code === 'ENOSPC') return 'no-space';
  if (code === 'ENOENT') return 'not-found';
  return 'write-failed';
}

function registerPdfExport(d) {
  d.ipcMain.handle('export-page-pdf', async (event, payload) => {
    if (!d.isMainSender(event)) return { success: false, error: 'forbidden' };
    const p = payload && typeof payload === 'object' ? payload : {};
    const wc = event.sender;
    if (!wc || wc.isDestroyed()) return { success: false, error: 'no-target' };
    const name = normalizePdfName(p.name);
    if (!name) return { success: false, error: 'bad-name' };
    const dirs = d.getSafeDirs() || [];
    const requested = typeof p.dir === 'string' ? d.path.resolve(p.dir) : '';
    const dir = dirs.filter((x) => requested && d.isPathInDir(requested, x))[0] || dirs[0];
    if (!dir) return { success: false, error: 'no-dir' };
    const target = d.path.join(dir, name);
    const audit = d.downloadSaveTarget.auditSaveTargetReal(dir, target, name);
    if (!audit || !audit.ok) return { success: false, error: 'unsafe-target' };
    try {
      const buf = await wc.printToPDF(buildPdfOptions(p.options));
      if (!buf || buf.length > MAX_PDF_BYTES) return { success: false, error: 'too-large' };
      await d.fs.promises.writeFile(audit.path, buf, { mode: 0o600, flag: 'wx' });
      return { success: true, path: audit.path, bytes: buf.length };
    } catch (e) {
      return { success: false, error: classifyPdfError(e) };
    }
  });
}

module.exports = { normalizePdfName, buildPdfOptions, classifyPdfError, registerPdfExport, MAX_PDF_BYTES };
