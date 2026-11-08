'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const journals = require('./downloadjournal');

function makeRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cosy-journal-'));
  return root;
}

function makeJournal(root, extra = {}) {
  return journals.createDownloadJournal({
    filePath: path.join(root, 'state', 'download-journal.json'),
    rootDir: root,
    ...extra,
  });
}

function sampleEntry(overrides = {}) {
  return {
    id: 'dl-1',
    url: 'https://cdn.example.org/a.zip',
    host: 'cdn.example.org',
    filename: 'a.zip',
    savePath: path.join(path.dirname(path.dirname(path.dirname(path.dirname('x')))), 'tmp'),
    totalBytes: 2048,
    receivedBytes: 512,
    state: journals.STATE.STARTED,
    startedAt: 1_700_000_000_000,
    ...overrides,
  };
}

test('missing file loads as empty', () => {
  const root = makeRoot();
  const journal = makeJournal(root);
  const loaded = journal.load();
  assert.deepEqual(loaded.entries, []);
  assert.deepEqual(loaded.rejected, []);
});

test('record persists and reloads', () => {
  const root = makeRoot();
  const now = 1_700_000_010_000;
  const journal = makeJournal(root, { now: () => now });
  const entry = sampleEntry({ savePath: path.join(root, 'a.zip') });
  const result = journal.record(entry);
  assert.equal(result.ok, true);
  const reloaded = makeJournal(root, { now: () => now }).load();
  assert.equal(reloaded.entries.length, 1);
  assert.equal(reloaded.entries[0].id, 'dl-1');
  assert.equal(reloaded.entries[0].filename, 'a.zip');
  assert.equal(reloaded.entries[0].state, journals.STATE.STARTED);
});

test('record rejects unsafe fields', () => {
  const root = makeRoot();
  const journal = makeJournal(root);
  assert.equal(journal.record(sampleEntry({ id: '../x' })).reason, journals.REASON.BAD_ID);
  assert.equal(journal.record(sampleEntry({ url: 'http://cdn.example.org/a.zip' })).reason, journals.REASON.BAD_URL);
  assert.equal(journal.record(sampleEntry({ filename: 'a/b.zip' })).reason, journals.REASON.BAD_FILENAME);
  assert.equal(journal.record(sampleEntry({ state: 'weird' })).reason, journals.REASON.BAD_STATE);
  assert.equal(journal.record(sampleEntry({ savePath: path.join(root, '..', 'x.zip') })).reason, journals.REASON.BAD_PATH);
});

test('update transitions a record to complete', () => {
  const root = makeRoot();
  const now = 1_700_000_010_000;
  const journal = makeJournal(root, { now: () => now });
  journal.record(sampleEntry({ savePath: path.join(root, 'a.zip') }));
  const updated = journal.update('dl-1', { state: journals.STATE.COMPLETE, receivedBytes: 2048 });
  assert.equal(updated.ok, true);
  assert.equal(updated.entry.state, journals.STATE.COMPLETE);
  assert.equal(journal.snapshot()[0].receivedBytes, 2048);
  assert.equal(journal.update('missing', { state: journals.STATE.COMPLETE }).ok, false);
});

test('stale entries are pruned on load and record', () => {
  const root = makeRoot();
  const now = 1_700_000_010_000;
  const journal = makeJournal(root, { now: () => now, retentionMs: 60_000 });
  journal.record(sampleEntry({ savePath: path.join(root, 'a.zip'), startedAt: now - 120_000 }));
  assert.equal(journal.snapshot().length, 0);
});

test('corrupted or oversized files load as empty', () => {
  const root = makeRoot();
  const stateDir = path.join(root, 'state');
  fs.mkdirSync(stateDir, { recursive: true });
  fs.writeFileSync(path.join(stateDir, 'download-journal.json'), '{not json');
  const corrupted = makeJournal(root).load();
  assert.deepEqual(corrupted.entries, []);
  assert.equal(corrupted.rejected[0], journals.REASON.BAD_SHAPE);
  fs.writeFileSync(path.join(stateDir, 'download-journal.json'), 'x'.repeat(journals.DEFAULT_MAX_FILE_BYTES + 1));
  const oversized = makeJournal(root).load();
  assert.deepEqual(oversized.entries, []);
  assert.equal(oversized.rejected[0], journals.REASON.TOO_LARGE);
});

test('interrupted entry without a part file is not resumable', () => {
  const root = makeRoot();
  const now = 1_700_000_010_000;
  const journal = makeJournal(root, { now: () => now });
  journal.record(sampleEntry({
    state: journals.STATE.INTERRUPTED,
    savePath: path.join(root, 'a.zip'),
    partPath: path.join(root, 'a.zip.part'),
    startedAt: now - 1000,
  }));
  const entry = journal.snapshot()[0];
  assert.equal(entry.resumable, false);
  assert.equal(entry.resumeReason, require('./downloadresume').REASON.PART_MISSING);
});

test('clear empties the journal', () => {
  const root = makeRoot();
  const journal = makeJournal(root);
  journal.record(sampleEntry({ savePath: path.join(root, 'a.zip') }));
  journal.clear();
  assert.deepEqual(journal.snapshot(), []);
  assert.deepEqual(makeJournal(root).load().entries, []);
});

test('describeJournalReject covers every reason', () => {
  for (const reason of Object.values(journals.REASON)) {
    const text = journals.describeJournalReject(reason);
    assert.equal(typeof text, 'string');
    assert.notEqual(text, '未知下载记录问题');
  }
});

test('reconcile marks completed entry whose file vanished', () => {
  const root = makeRoot();
  const journal = makeJournal(root);
  const savePath = path.join(root, 'gone.zip');
  journal.record(sampleEntry({
    savePath,
    state: journals.STATE.COMPLETE,
    receivedBytes: 2048,
    totalBytes: 2048,
    startedAt: Date.now() - 1000,
  }));
  const result = journal.reconcile({ exists: () => false });
  assert.equal(result.ok, true);
  assert.equal(result.summary.missing, 1);
  const entry = journal.snapshot()[0];
  assert.equal(entry.fileCheck, 'missing');
  const reloaded = makeJournal(root).load().entries[0];
  assert.equal(reloaded.id, 'dl-1');
});

test('reconcile flags size mismatch and keeps ok entries intact', () => {
  const root = makeRoot();
  const journal = makeJournal(root);
  journal.record(sampleEntry({ savePath: path.join(root, 'small.zip'), state: journals.STATE.COMPLETE, startedAt: Date.now() - 1000 }));
  journal.record(sampleEntry({ id: 'dl-2', filename: 'ok.zip', savePath: path.join(root, 'ok.zip'), state: journals.STATE.COMPLETE, startedAt: Date.now() - 1000, receivedBytes: 2048, totalBytes: 2048 }));
  const result = journal.reconcile({
    exists: () => true,
    sizeOf: (target) => (target.endsWith('small.zip') ? 10 : 2048),
  });
  assert.equal(result.summary.sizeMismatch, 1);
  assert.equal(result.summary.ok, 1);
  assert.equal(result.changes[0].id, 'dl-2');
  assert.deepEqual(result.changes.map((c) => c.to), ['ok', 'size-mismatch']);
});
