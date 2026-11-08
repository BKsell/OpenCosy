const EXPORT_VERSION = 1;
const REDACTED_PATH = '[local-path]';
const MAX_EXPORT_ENTRIES = 500;
const STATE_ORDER = ['started', 'downloading', 'complete', 'interrupted', 'error'];

function asText(value, limit = 200) {
  if (typeof value !== 'string') {
    return '';
  }
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, '');
  return cleaned.length > limit ? `${cleaned.slice(0, limit)}…` : cleaned;
}

function asBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) {
    return 0;
  }
  return Math.floor(n);
}

function hostOf(url) {
  try {
    const parsed = new URL(String(url || ''));
    return asText(parsed.host, 120);
  } catch (err) {
    return '';
  }
}

function baseName(pathText) {
  const text = asText(pathText, 260);
  if (!text) {
    return '';
  }
  const parts = text.split(/[\\/]/);
  return parts[parts.length - 1] || '';
}

function redactEntry(entry) {
  if (!entry || typeof entry !== 'object') {
    return null;
  }
  const id = asText(entry.id, 64);
  if (!id) {
    return null;
  }
  return {
    id,
    host: hostOf(entry.url),
    filename: asText(entry.filename, 160),
    state: asText(entry.state, 32),
    totalBytes: asBytes(entry.totalBytes),
    receivedBytes: asBytes(entry.receivedBytes),
    startedAt: asText(entry.startedAt, 40),
    updatedAt: asText(entry.updatedAt, 40),
    resumable: Boolean(entry.resumable),
    resumeReason: asText(entry.resumeReason, 40),
    fileCheck: asText(entry.fileCheck, 40),
    savePath: entry.savePath ? REDACTED_PATH : '',
    partPath: entry.partPath ? REDACTED_PATH : '',
    localName: baseName(entry.savePath || entry.partPath || entry.filename),
  };
}

function countStates(entries) {
  const counts = {};
  for (const state of STATE_ORDER) {
    counts[state] = 0;
  }
  for (const entry of entries) {
    const state = entry.state || 'unknown';
    counts[state] = (counts[state] || 0) + 1;
  }
  return counts;
}

function buildJournalExport(entries, options = {}) {
  const list = Array.isArray(entries) ? entries : [];
  const now = typeof options.now === 'string' && options.now ? options.now : new Date().toISOString();
  const redacted = [];
  let dropped = 0;
  for (const entry of list.slice(0, MAX_EXPORT_ENTRIES)) {
    const item = redactEntry(entry);
    if (item) {
      redacted.push(item);
    } else {
      dropped += 1;
    }
  }
  return {
    version: EXPORT_VERSION,
    generatedAt: now,
    total: list.length,
    exported: redacted.length,
    dropped: dropped + Math.max(0, list.length - MAX_EXPORT_ENTRIES),
    states: countStates(redacted),
    entries: redacted,
  };
}

function describeExport(payload) {
  if (!payload || !Array.isArray(payload.entries)) {
    return '下载台账导出不可用';
  }
  const states = payload.states || {};
  const pieces = STATE_ORDER.filter((state) => (states[state] || 0) > 0)
    .map((state) => `${state} ${states[state]}`);
  const head = `导出 ${payload.exported}/${payload.total} 条下载记录`;
  if (pieces.length === 0) {
    return head;
  }
  return `${head}（${pieces.join('，')}）`;
}

function exportContainsLocalPaths(payload) {
  if (!payload || !Array.isArray(payload.entries)) {
    return false;
  }
  return payload.entries.some((entry) => {
    if (!entry) {
      return false;
    }
    const fields = [entry.savePath, entry.partPath];
    return fields.some((field) => typeof field === 'string' && field !== '' && field !== REDACTED_PATH);
  });
}

module.exports = {
  EXPORT_VERSION,
  REDACTED_PATH,
  MAX_EXPORT_ENTRIES,
  buildJournalExport,
  describeExport,
  exportContainsLocalPaths,
};
