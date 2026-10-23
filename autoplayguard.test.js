'use strict';

// autoplayguard.test.js —— 带声/静音自动播放、手势/参与度、后台音、并发上限、重试风暴、WebAudio resume、setSinkId。

const test = require('node:test');
const assert = require('node:assert/strict');
const ap = require('./autoplayguard');
const { AutoplayGuard, AP_REASON, AP_MUTED_ONLY, defaultAutoplayPolicy } = ap;

function ctx(over) {
  return Object.assign({
    origin: 'https://video.example.com', blocked: false,
    hasUserGesture: false, isBackground: false, now: 0,
  }, over || {});
}

const AUDIO = { muted: false, hasAudioTrack: true, isVideo: false };
const MUTED = { muted: true, hasAudioTrack: true, isVideo: true };
const SILENT_VIDEO = { muted: false, hasAudioTrack: false, isVideo: true };

test('无参与度带声自动播放降级静音', () => {
  const g = new AutoplayGuard();
  assert.equal(g.decidePlay(ctx(), AUDIO).decision, AP_MUTED_ONLY);
});

test('手势后带声放行', () => {
  const g = new AutoplayGuard();
  assert.equal(g.decidePlay(ctx({ hasUserGesture: true }), AUDIO).decision, 'allow');
});

test('静音自动播放放行', () => {
  const g = new AutoplayGuard();
  assert.equal(g.decidePlay(ctx(), MUTED).decision, 'allow');
});

test('无音轨视频放行（不触发声音门）', () => {
  const g = new AutoplayGuard();
  assert.equal(g.decidePlay(ctx(), SILENT_VIDEO).decision, 'allow');
});

test('后台带声拒绝（即便有参与度也拦后台）', () => {
  const g = new AutoplayGuard();
  assert.equal(g.decidePlay(ctx({ hasUserGesture: true, isBackground: true }), AUDIO).reason, AP_REASON.BACKGROUND_AUDIO);
});

test('高参与度来源可带声自动播放', () => {
  const pol = defaultAutoplayPolicy();
  pol.highEngagementOrigins = ['music.example.com'];
  const g = new AutoplayGuard(pol);
  assert.equal(g.decidePlay(ctx({ origin: 'https://music.example.com' }), AUDIO).decision, 'allow');
});

test('并发媒体上限', () => {
  const pol = defaultAutoplayPolicy();
  pol.maxConcurrentPlayingMedia = 2;
  const g = new AutoplayGuard(pol);
  assert.equal(g.decidePlay(ctx(), MUTED).decision, 'allow');
  assert.equal(g.decidePlay(ctx(), SILENT_VIDEO).decision, 'allow');
  assert.equal(g.decidePlay(ctx(), MUTED).reason, AP_REASON.TOO_MANY_CONCURRENT_MEDIA);
});

test('play 重试风暴：超频与超额都拒', () => {
  const g = new AutoplayGuard();
  assert.equal(g.notePlayRejected('https://video.example.com', 0).retry, true);
  assert.equal(g.notePlayRejected('https://video.example.com', 100).retry, false); // 太密
  const g2 = new AutoplayGuard();
  let last;
  for (let i = 0; i < 5; i++) last = g2.notePlayRejected('https://video.example.com', i * 1000);
  assert.equal(last.retry, false); // 超次数
});

test('WebAudio resume 无手势拒绝', () => {
  const g = new AutoplayGuard();
  assert.equal(g.decideAudioContextResume(ctx()).reason, AP_REASON.WEBAUDIO_RESUME_NO_GESTURE);
  assert.equal(g.decideAudioContextResume(ctx({ hasUserGesture: true })).allowed, true);
});

test('setSinkId 默认拒绝（设备枚举）', () => {
  const g = new AutoplayGuard();
  assert.equal(g.decideSetSinkId(ctx({ hasUserGesture: true })).reason, AP_REASON.SINKID_DEVICE_ENUM);
});
