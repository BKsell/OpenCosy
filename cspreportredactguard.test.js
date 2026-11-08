'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./cspreportredactguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows plain report', () => {
  const result = guard.evaluateCspReport({ 'csp-report': { 'document-uri': 'https://example.com/page' } });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks non object report', () => {
  const result = guard.evaluateCspReport(null);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.NOT_OBJECT);
});

test('blocks secret query in document uri', () => {
  const result = guard.evaluateCspReport({ 'csp-report': { 'document-uri': 'https://example.com/login?token=abc' } });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks secret referrer', () => {
  const result = guard.evaluateCspReport({ 'csp-report': { 'document-uri': 'https://example.com/page', referrer: 'https://example.com/x?session=1' } });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.SECRET_QUERY);
});

test('blocks control characters', () => {
  const result = guard.evaluateCspReport({ 'csp-report': { 'document-uri': 'https://example.com/x', referrer: 'https://example.com/' } });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.CONTROL_CHARS);
});

