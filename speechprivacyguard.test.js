'use strict';

// speechprivacyguard.test.js —— 识别启动门、continuous、后台开麦、节流、转写敏感、合成超长、远程嗓音。

const test = require('node:test');
const assert = require('node:assert/strict');
const sp = require('./speechprivacyguard');
const { SpeechPrivacyGuard, SP_REASON, transcriptLooksSensitive } = sp;

function ctx(over) {
  return Object.assign({
    origin: 'https://voice.example.com', isSecureContext: true, blocked: false,
    isBackground: false, hasUserGesture: true, now: 0,
  }, over || {});
}

test('转写敏感：中文关键词', () => {
  assert.ok(transcriptLooksSensitive('我的身份证号是多少'));
  assert.ok(transcriptLooksSensitive('请输入验证码'));
  assert.ok(!transcriptLooksSensitive('今天天气不错'));
});

test('转写敏感：长数字串视作卡号', () => {
  assert.ok(transcriptLooksSensitive('卡号 4111111111111111 对'));
  assert.ok(!transcriptLooksSensitive('电话是 12345'));
});

test('转写敏感：英文关键词', () => {
  assert.ok(transcriptLooksSensitive('my credit card number'));
  assert.ok(transcriptLooksSensitive('the CVV is'));
});

test('非安全上下文拒绝识别', () => {
  const g = new SpeechPrivacyGuard();
  assert.equal(g.decideRecognitionStart(ctx({ isSecureContext: false }), {}).reason, SP_REASON.INSECURE_CONTEXT);
});

test('后台开麦拒绝', () => {
  const g = new SpeechPrivacyGuard();
  assert.equal(g.decideRecognitionStart(ctx({ isBackground: true }), {}).reason, SP_REASON.MIC_BACKGROUND);
});

test('无手势拒绝识别', () => {
  const g = new SpeechPrivacyGuard();
  assert.equal(g.decideRecognitionStart(ctx({ hasUserGesture: false }), {}).reason, SP_REASON.MIC_NO_GESTURE);
});

test('continuous 默认拒绝', () => {
  const g = new SpeechPrivacyGuard();
  assert.equal(g.decideRecognitionStart(ctx({ now: 0 }), { continuous: true }).reason, SP_REASON.CONTINUOUS_FORBIDDEN);
});

test('合法单次识别放行', () => {
  const g = new SpeechPrivacyGuard();
  assert.equal(g.decideRecognitionStart(ctx({ now: 0 }), { continuous: false }).allowed, true);
});

test('启动节流', () => {
  const g = new SpeechPrivacyGuard();
  g.decideRecognitionStart(ctx({ now: 0 }), {});
  assert.equal(g.decideRecognitionStart(ctx({ now: 1000 }), {}).reason, SP_REASON.START_THROTTLED);
});

test('敏感转写检查', () => {
  const g = new SpeechPrivacyGuard();
  assert.equal(g.inspectTranscript('你的银行卡密码').sensitive, true);
  assert.equal(g.inspectTranscript('普通闲聊内容').sensitive, false);
});

test('合成超长文本拒绝', () => {
  const g = new SpeechPrivacyGuard();
  assert.equal(g.decideUtterance('x'.repeat(1001), { localService: true }).reason, SP_REASON.UTTERANCE_TOO_LONG);
});

test('远程嗓音默认拒绝，本地放行', () => {
  const g = new SpeechPrivacyGuard();
  assert.equal(g.decideUtterance('你好', { localService: false }).reason, SP_REASON.REMOTE_VOICE_FORBIDDEN);
  assert.equal(g.decideUtterance('你好', { localService: true }).allowed, true);
});
