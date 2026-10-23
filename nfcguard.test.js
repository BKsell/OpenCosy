'use strict';

// nfcguard.test.js —— Web NFC：扫描手势/可见性、持久后台扫描、写入 URL scheme/mediaType/体积。

const test = require('node:test');
const assert = require('node:assert/strict');
const n = require('./nfcguard');
const { NfcGuard, NFC_REASON, validateRecord, defaultNfcPolicy, recordUrlScheme } = n;

function ctx(over) {
  return Object.assign({ origin: 'https://app.example.com', isTopFrame: true, userGesture: true, visible: true }, over || {});
}

test('可见且带手势允许扫描', () => {
  const g = new NfcGuard();
  assert.equal(g.decideScan(ctx()).decision, 'allow');
});

test('页面隐藏时拒绝扫描', () => {
  const g = new NfcGuard();
  assert.equal(g.decideScan(ctx({ visible: false })).reason, NFC_REASON.SCAN_WHEN_HIDDEN);
});

test('持久后台扫描拒绝', () => {
  const g = new NfcGuard();
  assert.equal(g.decideScan(ctx({ visible: true }), { persistent: true, visible: false }).decision, 'allow');
  // 显式 persistent 且当前不可见 → 拒。
  assert.equal(g.decideScan(ctx({ visible: false }), { persistent: true }).reason, NFC_REASON.SCAN_WHEN_HIDDEN);
});

test('独占重复扫描拒绝', () => {
  const g = new NfcGuard();
  g.decideScan(ctx());
  assert.equal(g.decideScan(ctx(), { exclusive: true }).reason, NFC_REASON.PERSISTENT_SCAN);
});

test('无手势/子框架/非 https 扫描拒绝', () => {
  const g = new NfcGuard();
  assert.equal(g.decideScan(ctx({ userGesture: false })).reason, NFC_REASON.NO_GESTURE);
  assert.equal(g.decideScan(ctx({ isTopFrame: false })).reason, NFC_REASON.CROSS_ORIGIN_SUBFRAME);
  assert.equal(g.decideScan(ctx({ origin: 'http://x' })).reason, NFC_REASON.INSECURE_ORIGIN);
});

test('写入 https URL 记录放行', () => {
  const g = new NfcGuard();
  const r = g.decideWrite(ctx(), [{ recordType: 'url', data: 'https://pay.example.com/confirm' }]);
  assert.equal(r.decision, 'allow');
});

test('写入 http URL 默认拒绝', () => {
  const g = new NfcGuard();
  const r = g.decideWrite(ctx(), [{ recordType: 'url', data: 'http://pay.example.com/' }]);
  assert.equal(r.reason, NFC_REASON.INSECURE_RECORD_URL);
});

test('写入外部 scheme（tel/intent）拒绝', () => {
  const g = new NfcGuard();
  const r = g.decideWrite(ctx(), [{ recordType: 'absolute-url', data: 'intent://x/#Intent;end' }]);
  assert.equal(r.reason, NFC_REASON.EXTERNAL_SCHEME_RECORD);
});

test('写入未知/禁写记录类型拒绝', () => {
  const g = new NfcGuard();
  assert.equal(g.decideWrite(ctx(), [{ recordType: 'empty' }]).reason, NFC_REASON.RECORD_TYPE_NOT_ALLOWED);
  assert.equal(g.decideWrite(ctx(), [{ recordType: 'bogus' }]).reason, NFC_REASON.RECORD_TYPE_NOT_ALLOWED);
});

test('mime 记录 mediaType 控制字符/超长拒绝', () => {
  const g = new NfcGuard();
  assert.equal(g.decideWrite(ctx(), [{ recordType: 'mime', mediaType: 'text/pl\nain', data: 'x' }]).reason,
    NFC_REASON.MEDIA_TYPE_CONTROL_CHAR);
  const longMt = 'a/' + 'b'.repeat(260);
  assert.equal(g.decideWrite(ctx(), [{ recordType: 'mime', mediaType: longMt, data: 'x' }]).reason,
    NFC_REASON.MEDIA_TYPE_TOO_LONG);
});

test('写入超大载荷拒绝', () => {
  const g = new NfcGuard();
  const big = 'x'.repeat(40000);
  assert.equal(g.decideWrite(ctx(), [{ recordType: 'text', data: big }]).reason, NFC_REASON.PAYLOAD_TOO_LARGE);
});

test('隐藏页面写入拒绝', () => {
  const g = new NfcGuard();
  assert.equal(g.decideWrite(ctx({ visible: false }), [{ recordType: 'text', data: 'hi' }]).reason,
    NFC_REASON.WRITE_NOT_VISIBLE);
});

test('pageHidden/endScan 生命周期', () => {
  const g = new NfcGuard();
  g.decideScan(ctx());
  assert.equal(g.pageHidden('https://app.example.com'), true);
  g.endScan('https://app.example.com');
  assert.equal(g.pageHidden('https://app.example.com'), false);
});

test('validateRecord 与 scheme 纯函数', () => {
  const pol = defaultNfcPolicy();
  assert.equal(validateRecord(null, pol).ok, false);
  assert.equal(recordUrlScheme('https://a.com'), 'https');
  assert.equal(recordUrlScheme('tel:123'), 'tel');
  assert.equal(recordUrlScheme('noscheme'), '');
});
