'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./windowboundsguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows visible window', () => {
  const result = guard.evaluateWindowBounds({ x: 0, y: 0, width: 800, height: 600 }, [{ workArea: { x: 0, y: 0, width: 1920, height: 1080 } }]);
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks zero size window', () => {
  const result = guard.evaluateWindowBounds({ x: 0, y: 0, width: 0, height: 600 }, [{ workArea: { x: 0, y: 0, width: 1920, height: 1080 } }]);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.ZERO_SIZE);
});

test('blocks oversized window', () => {
  const result = guard.evaluateWindowBounds({ x: 0, y: 0, width: 20000, height: 600 }, [{ workArea: { x: 0, y: 0, width: 1920, height: 1080 } }]);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TOO_LARGE);
});

test('blocks offscreen window', () => {
  const result = guard.evaluateWindowBounds({ x: 8000, y: 0, width: 800, height: 600 }, [{ workArea: { x: 0, y: 0, width: 1920, height: 1080 } }]);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.OFFSCREEN);
});

test('allows minimized window', () => {
  const result = guard.evaluateWindowBounds({ x: 8000, y: 0, width: 800, height: 600, minimized: true }, [{ workArea: { x: 0, y: 0, width: 1920, height: 1080 } }]);
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.MINIMIZED_OFFSCREEN);
});

test('blocks missing display', () => {
  const result = guard.evaluateWindowBounds({ x: 0, y: 0, width: 800, height: 600 }, []);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.INVALID_DISPLAY);
});

