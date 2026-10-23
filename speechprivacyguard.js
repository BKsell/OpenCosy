'use strict';

// speechprivacyguard.js —— Web Speech（SpeechRecognition 语音识别 / SpeechSynthesis 朗读）
// 隐私裁决内核。
//
// 威胁模型：
//   1. SpeechRecognition 持续监听麦克风，把环境音/谈话转写上传到浏览器厂商或第三方
//      语音服务；后台/失焦仍在监听是典型窃听；
//   2. 识别可被无手势启动，页面一加载就开麦；continuous=true + interimResults 最大化采集；
//   3. onresult 转写文本里可能含身份证号/卡号/地址等口播敏感信息，直接外发；
//   4. SpeechSynthesis 被用于无障碍通道注入（朗读伪造的系统提示）做社工，或高频朗读
//      烦人/焦点劫持；超长文本占资源；
//   5. 选择非本地 voice（remote 语音服务）把待朗读文本上传第三方。
//
// 纯逻辑：识别启动门、连续/临时结果限制、合成文本敏感扫描与远程嗓音裁决。

const SP_DENY = 'deny';
const SP_ALLOW = 'allow';

const SP_REASON = Object.freeze({
  INSECURE_CONTEXT: 'sp-insecure-context',
  BAD_ORIGIN: 'sp-bad-origin',
  BLOCKED_ORIGIN: 'sp-blocked-origin',
  MIC_BACKGROUND: 'sp-mic-background',
  MIC_NO_GESTURE: 'sp-mic-no-gesture',
  CONTINUOUS_FORBIDDEN: 'sp-continuous-forbidden',
  START_THROTTLED: 'sp-start-throttled',
  UTTERANCE_TOO_LONG: 'sp-utterance-too-long',
  REMOTE_VOICE_FORBIDDEN: 'sp-remote-voice-forbidden',
  SENSITIVE_TRANSCRIPT: 'sp-sensitive-transcript',
});

function defaultSpeechPolicy() {
  return {
    requireSecureContext: true,
    micDenyBackground: true,
    micRequireGesture: true,
    allowContinuous: false,
    startMinIntervalMs: 3000,
    maxUtteranceChars: 1000,
    allowRemoteVoice: false,
    scanTranscriptSensitivity: true,
  };
}

function originKey(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  const rest = origin.slice(idx + 3);
  if (rest === '' || rest.indexOf('/') >= 0 || rest.indexOf('?') >= 0) return '';
  return scheme + '://' + rest.toLowerCase();
}

// 口播敏感片段（纯字符包含匹配，不用正则）。
const SENSITIVE_MARKERS = Object.freeze([
  '身份证', '银行卡', '验证码', '密码', '信用卡', '社保',
  'social security', 'credit card', 'cvv', 'pin code', 'one-time password',
]);

function transcriptLooksSensitive(text) {
  if (typeof text !== 'string') return false;
  const lower = text.toLowerCase();
  for (const m of SENSITIVE_MARKERS) {
    if (lower.indexOf(m) >= 0) return true;
  }
  // 连续 15~19 位数字视作卡号口播。
  let run = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 48 && c <= 57) { run++; if (run >= 15) return true; }
    else run = 0;
  }
  return false;
}

class SpeechPrivacyGuard {
  constructor(policy) {
    this.policy = policy || defaultSpeechPolicy();
    this.lastStart = new Map();
  }

  // decideRecognitionStart 裁决 webkitSpeechRecognition.start()。
  // cfg: {continuous, interimResults}
  decideRecognitionStart(ctx, cfg) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { allowed: false, reason: SP_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { allowed: false, reason: SP_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { allowed: false, reason: SP_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { allowed: false, reason: SP_REASON.BLOCKED_ORIGIN };
    if (pol.micDenyBackground && ctx.isBackground === true) {
      return { allowed: false, reason: SP_REASON.MIC_BACKGROUND };
    }
    if (pol.micRequireGesture && ctx.hasUserGesture !== true) {
      return { allowed: false, reason: SP_REASON.MIC_NO_GESTURE };
    }
    if (cfg && cfg.continuous === true && !pol.allowContinuous) {
      return { allowed: false, reason: SP_REASON.CONTINUOUS_FORBIDDEN };
    }
    const now = ctx.now || 0;
    if (this.lastStart.has(key) && now - this.lastStart.get(key) < pol.startMinIntervalMs) {
      return { allowed: false, reason: SP_REASON.START_THROTTLED };
    }
    this.lastStart.set(key, now);
    return { allowed: true, reason: '' };
  }

  // inspectTranscript 检查识别结果文本。
  inspectTranscript(text) {
    if (!this.policy.scanTranscriptSensitivity) return { sensitive: false };
    if (transcriptLooksSensitive(text)) return { sensitive: true, reason: SP_REASON.SENSITIVE_TRANSCRIPT };
    return { sensitive: false };
  }

  // decideUtterance 裁决 speechSynthesis.speak(u)。
  decideUtterance(text, voice) {
    if (typeof text === 'string' && text.length > this.policy.maxUtteranceChars) {
      return { allowed: false, reason: SP_REASON.UTTERANCE_TOO_LONG };
    }
    if (voice && voice.localService === false && !this.policy.allowRemoteVoice) {
      return { allowed: false, reason: SP_REASON.REMOTE_VOICE_FORBIDDEN };
    }
    return { allowed: true, reason: '' };
  }
}

module.exports = {
  SP_ALLOW, SP_DENY, SP_REASON,
  defaultSpeechPolicy, transcriptLooksSensitive, SENSITIVE_MARKERS, SpeechPrivacyGuard,
};
