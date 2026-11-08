'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./clearsitedataguard');

test('missing header is untouched', () => {
  const headers = {};
  const result = guard.applyClearSiteDataGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('known tokens are kept', () => {
  const headers = { 'clear-site-data': '"cache", "cookies", "storage"' };
  const result = guard.applyClearSiteDataGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(headers['clear-site-data'], '"cache", "cookies", "storage"');
});

test('unknown token is removed and header rewritten', () => {
  const headers = { 'clear-site-data': '"cache", "credentials", "storage"' };
  const result = guard.applyClearSiteDataGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.UNKNOWN_TOKEN);
  assert.deepEqual(result.kept, ['cache', 'storage']);
  assert.deepEqual(headers['clear-site-data'], ['"cache", "storage"']);
});

test('unquoted tokens are normalised', () => {
  const headers = { 'Clear-Site-Data': 'cache,cookies' };
  const result = guard.applyClearSiteDataGuard(headers);
  assert.equal(result.changed, true);
  assert.deepEqual(headers['Clear-Site-Data'], ['"cache", "cookies"']);
});

test('wildcard is reported', () => {
  const headers = { 'clear-site-data': '"*", "cache"' };
  const result = guard.applyClearSiteDataGuard(headers);
  assert.equal(result.reason, guard.REASON.WILDCARD);
  assert.deepEqual(result.kept, ['*', 'cache']);
});

test('all unknown tokens removes the header', () => {
  const headers = { 'clear-site-data': '"credential", "password"' };
  const result = guard.applyClearSiteDataGuard(headers);
  assert.equal(result.reason, guard.REASON.UNKNOWN_TOKEN);
  assert.equal(headers['clear-site-data'], undefined);
});

test('empty header is removed', () => {
  const headers = { 'clear-site-data': ' , ' };
  const result = guard.applyClearSiteDataGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
  assert.equal(headers['clear-site-data'], undefined);
});

test('overlong header is removed', () => {
  const headers = { 'clear-site-data': '"' + 'a'.repeat(guard.MAX_VALUE_LENGTH) + '"' };
  const result = guard.applyClearSiteDataGuard(headers);
  assert.equal(result.reason, guard.REASON.TOO_LONG);
  assert.equal(headers['clear-site-data'], undefined);
});

test('too many tokens are removed', () => {
  const list = [];
  for (let i = 0; i < guard.MAX_TOKENS + 2; i += 1) {
    list.push('"cache"');
  }
  const headers = { 'clear-site-data': list.join(', ') };
  const result = guard.applyClearSiteDataGuard(headers);
  assert.equal(result.reason, guard.REASON.TOO_MANY);
  assert.equal(headers['clear-site-data'], undefined);
});

test('execution contexts token is accepted case-insensitively', () => {
  const headers = { 'clear-site-data': '"executionContexts"' };
  const result = guard.applyClearSiteDataGuard(headers);
  assert.equal(result.changed, true);
  assert.deepEqual(headers['clear-site-data'], ['"executioncontexts"']);
});

test('tokensOf strips quotes and blanks', () => {
  assert.deepEqual(guard.tokensOf('"cache", , "storage"'), ['cache', 'storage']);
});

test('describeReason covers branches', () => {
  assert.equal(guard.describeReason(guard.REASON.MISSING), '响应未声明本地状态清理');
  assert.equal(guard.describeReason('other'), '本地状态清理目标合法');
});
