'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./reporttoguard');

function he(value) {
  return { 'reporting-endpoints': [value] };
}

function hr(value) {
  return { 'report-to': [value] };
}

test('缺头返回 missing 且不改动', () => {
  const headers = {};
  const r = guard.applyReportingEndpointsGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规端点不改动', () => {
  const headers = he('default="https://example.com/reports"');
  const r = guard.applyReportingEndpointsGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('明文端点被剔除', () => {
  const headers = he('default="http://example.com/reports"');
  const r = guard.applyReportingEndpointsGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INSECURE_ENDPOINT);
  assert.strictEqual(headers['reporting-endpoints'], undefined);
});

test('内嵌凭据端点被剔除', () => {
  const headers = he('default="https://user:pw@example.com/r"');
  const r = guard.applyReportingEndpointsGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.ENDPOINT_CREDENTIALS);
});

test('路径穿越端点被剔除', () => {
  const headers = he('default="https://example.com/../internal"');
  const r = guard.applyReportingEndpointsGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.ENDPOINT_PATH_SHAPE);
});

test('缺少等号的声明被剔除', () => {
  const headers = he('broken, default="https://example.com/r"');
  const r = guard.applyReportingEndpointsGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['reporting-endpoints'][0], 'default="https://example.com/r"');
});

test('多端点混合只保留合规项', () => {
  const headers = he('default="https://example.com/r", nel="http://example.com/n"');
  const r = guard.applyReportingEndpointsGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INSECURE_ENDPOINT);
  assert.strictEqual(headers['reporting-endpoints'][0], 'default="https://example.com/r"');
});

test('端点配置超长整头剥除', () => {
  const headers = he(`default="https://example.com/${'a'.repeat(2200)}"`);
  const r = guard.applyReportingEndpointsGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('legacy report-to 合规不改动', () => {
  const headers = hr('[{"group":"default","max_age":3600,"endpoints":[{"url":"https://example.com/r"}]}]');
  const r = guard.applyReportToGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('legacy 非法 JSON 被剥除', () => {
  const headers = hr('{not json');
  const r = guard.applyReportToGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['report-to'], undefined);
});

test('legacy 明文端点被剔除', () => {
  const headers = hr('[{"group":"default","max_age":60,"endpoints":[{"url":"http://example.com/r"}]}]');
  const r = guard.applyReportToGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INSECURE_ENDPOINT);
});

test('legacy 缓存时长超限被剔除', () => {
  const headers = hr('[{"group":"default","max_age":9999999,"endpoints":[{"url":"https://example.com/r"}]}]');
  const r = guard.applyReportToGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_MAX_AGE);
});

test('legacy 未知分组被剔除', () => {
  const headers = hr('[{"group":"attacker","max_age":60,"endpoints":[{"url":"https://example.com/r"}]}]');
  const r = guard.applyReportToGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_GROUP);
});

test('legacy 空端点数组被剔除', () => {
  const headers = hr('[{"group":"default","max_age":60,"endpoints":[]}]');
  const r = guard.applyReportToGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('描述覆盖所有状态', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
