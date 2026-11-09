'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const resume = require('./downloadresume');

const ROOT = path.join(os.tmpdir(), 'cosy-resume-root');

function entry(overrides = {}) {
  const base = {
    url: 'https://cdn.example.org/files/archive.zip',
    host: 'cdn.example.org',
    partPath: path.join(ROOT, 'archive.zip.part'),
    receivedBytes: 1024,
    totalBytes: 4096,
    startedAt: 1_700_000_000_000,
    state: 'interrupted',
  };
  return { ...base, ...overrides };
}

const NOW = 1_700_000_010_000;

test('resumable entry passes every gate', () => {
  const verdict = resume.auditResumeCandidate(entry(), {
    rootDir: ROOT,
    now: NOW,
    exists: () => true,
    sizeOf: () => 1024,
  });
  assert.equal(verdict.resumable, true);
  assert.equal(verdict.reason, resume.REASON.OK);
  assert.equal(verdict.offset, 1024);
});

test('non https url is rejected', () => {
  const verdict = resume.auditResumeCandidate(entry({ url: 'http://cdn.example.org/a.zip' }), { now: NOW });
  assert.equal(verdict.reason, resume.REASON.BAD_SCHEME);
});

test('userinfo in url is rejected', () => {
  const verdict = resume.auditResumeCandidate(entry({ url: 'https://user:pw@cdn.example.org/a.zip' }), { now: NOW });
  assert.equal(verdict.reason, resume.REASON.BAD_URL);
});

test('host mismatch is rejected', () => {
  const verdict = resume.auditResumeCandidate(entry({ host: 'evil.example.org' }), { now: NOW });
  assert.equal(verdict.reason, resume.REASON.BAD_HOST);
});

test('part path outside root is rejected', () => {
  const verdict = resume.auditResumeCandidate(entry({ partPath: path.join(ROOT, '..', 'escape.part') }), {
    rootDir: ROOT,
    now: NOW,
  });
  assert.equal(verdict.reason, resume.REASON.BAD_PATH);
});

test('missing part file is rejected', () => {
  const verdict = resume.auditResumeCandidate(entry(), { rootDir: ROOT, now: NOW, exists: () => false });
  assert.equal(verdict.reason, resume.REASON.PART_MISSING);
});

test('size mismatch is rejected', () => {
  const verdict = resume.auditResumeCandidate(entry(), {
    rootDir: ROOT,
    now: NOW,
    exists: () => true,
    sizeOf: () => 900,
  });
  assert.equal(verdict.reason, resume.REASON.SIZE_MISMATCH);
});

test('stale entry is rejected', () => {
  const verdict = resume.auditResumeCandidate(entry(), { now: NOW + resume.DEFAULT_MAX_AGE_MS + 1 });
  assert.equal(verdict.reason, resume.REASON.STALE);
});

test('byte counters are validated', () => {
  const verdict = resume.auditResumeCandidate(entry({ receivedBytes: 9000 }), { now: NOW });
  assert.equal(verdict.reason, resume.REASON.BAD_BYTES);
  const negative = resume.auditResumeCandidate(entry({ receivedBytes: -1 }), { now: NOW });
  assert.equal(negative.reason, resume.REASON.BAD_BYTES);
  const huge = resume.auditResumeCandidate(entry({ receivedBytes: 1, totalBytes: resume.DEFAULT_MAX_TOTAL_BYTES + 1 }), { now: NOW });
  assert.equal(huge.reason, resume.REASON.TOO_LARGE);
});

test('malformed candidates are rejected', () => {
  assert.equal(resume.auditResumeCandidate(null, { now: NOW }).reason, resume.REASON.BAD_SHAPE);
  assert.equal(resume.auditResumeCandidate('x', { now: NOW }).reason, resume.REASON.BAD_SHAPE);
  assert.equal(resume.auditResumeCandidate(entry({ url: '' }), { now: NOW }).reason, resume.REASON.BAD_URL);
});

test('describeResumeReject covers every reason', () => {
  for (const reason of Object.values(resume.REASON)) {
    const text = resume.describeResumeReject(reason);
    assert.equal(typeof text, 'string');
    assert.notEqual(text, '未知续传问题');
  }
});
