const test = require('node:test');
const assert = require('node:assert');
const exporter = require('./downloadjournalexport');

function entry(overrides = {}) {
  return {
    id: 'dl-1',
    url: 'https://example.com/files/pack.zip',
    filename: 'pack.zip',
    savePath: 'C:\\Users\\shell\\Downloads\\pack.zip',
    partPath: 'C:\\Users\\shell\\Downloads\\pack.zip.part',
    state: 'downloading',
    totalBytes: 1000,
    receivedBytes: 512,
    startedAt: '2026-11-07T01:00:00.000Z',
    updatedAt: '2026-11-07T01:01:00.000Z',
    resumable: true,
    resumeReason: 'partial-file-present',
    fileCheck: 'sha256',
    ...overrides,
  };
}

test('buildJournalExport redacts local paths', () => {
  const payload = exporter.buildJournalExport([entry()], { now: '2026-11-07T02:00:00.000Z' });
  assert.strictEqual(payload.version, exporter.EXPORT_VERSION);
  assert.strictEqual(payload.generatedAt, '2026-11-07T02:00:00.000Z');
  assert.strictEqual(payload.exported, 1);
  assert.strictEqual(payload.entries[0].savePath, exporter.REDACTED_PATH);
  assert.strictEqual(payload.entries[0].partPath, exporter.REDACTED_PATH);
  assert.strictEqual(payload.entries[0].localName, 'pack.zip');
  assert.strictEqual(payload.entries[0].host, 'example.com');
  assert.strictEqual(exporter.exportContainsLocalPaths(payload), false);
});

test('buildJournalExport drops entries without id', () => {
  const payload = exporter.buildJournalExport([entry({ id: '' }), entry({ id: 'dl-2' })], { now: 'x' });
  assert.strictEqual(payload.total, 2);
  assert.strictEqual(payload.exported, 1);
  assert.strictEqual(payload.dropped, 1);
});

test('buildJournalExport caps exported entries', () => {
  const many = [];
  for (let i = 0; i < exporter.MAX_EXPORT_ENTRIES + 20; i += 1) {
    many.push(entry({ id: `dl-${i}` }));
  }
  const payload = exporter.buildJournalExport(many, { now: 'x' });
  assert.strictEqual(payload.exported, exporter.MAX_EXPORT_ENTRIES);
  assert.strictEqual(payload.dropped, 20);
  assert.ok(payload.entries.length <= exporter.MAX_EXPORT_ENTRIES);
});

test('buildJournalExport strips control characters and clamps sizes', () => {
  const payload = exporter.buildJournalExport([
    entry({ filename: 'pa\u0000ck\u001b.zip', totalBytes: -3, receivedBytes: 'abc' }),
  ], { now: 'x' });
  assert.strictEqual(payload.entries[0].filename, 'pack.zip');
  assert.strictEqual(payload.entries[0].totalBytes, 0);
  assert.strictEqual(payload.entries[0].receivedBytes, 0);
});

test('buildJournalExport counts states', () => {
  const payload = exporter.buildJournalExport([
    entry({ id: 'a', state: 'complete' }),
    entry({ id: 'b', state: 'error' }),
    entry({ id: 'c', state: 'error' }),
  ], { now: 'x' });
  assert.strictEqual(payload.states.complete, 1);
  assert.strictEqual(payload.states.error, 2);
  assert.strictEqual(payload.states.started, 0);
});

test('buildJournalExport tolerates bad input', () => {
  const payload = exporter.buildJournalExport(null, {});
  assert.strictEqual(payload.total, 0);
  assert.strictEqual(payload.exported, 0);
  assert.ok(typeof payload.generatedAt === 'string' && payload.generatedAt.length > 0);
  assert.strictEqual(exporter.exportContainsLocalPaths(null), false);
});

test('buildJournalExport keeps missing paths empty', () => {
  const payload = exporter.buildJournalExport([entry({ savePath: '', partPath: '' })], { now: 'x' });
  assert.strictEqual(payload.entries[0].savePath, '');
  assert.strictEqual(payload.entries[0].localName, 'pack.zip');
});

test('describeExport summarises states', () => {
  const payload = exporter.buildJournalExport([
    entry({ id: 'a', state: 'complete' }),
    entry({ id: 'b', state: 'interrupted' }),
  ], { now: 'x' });
  const text = exporter.describeExport(payload);
  assert.ok(text.includes('2/2'));
  assert.ok(text.includes('complete 1'));
  assert.ok(text.includes('interrupted 1'));
  assert.strictEqual(exporter.describeExport(null), '下载台账导出不可用');
});

test('exportContainsLocalPaths detects leaked absolute paths', () => {
  const fake = { entries: [{ savePath: 'C:\\secret\\a.zip', partPath: '' }] };
  assert.strictEqual(exporter.exportContainsLocalPaths(fake), true);
});

test('buildJournalExport tolerates unparsable urls', () => {
  const payload = exporter.buildJournalExport([entry({ url: 'not a url' })], { now: 'x' });
  assert.strictEqual(payload.entries[0].host, '');
});

test('buildJournalExport keeps resumable flags', () => {
  const payload = exporter.buildJournalExport([entry({ resumable: false, resumeReason: '' })], { now: 'x' });
  assert.strictEqual(payload.entries[0].resumable, false);
  assert.strictEqual(payload.entries[0].resumeReason, '');
});
