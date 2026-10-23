'use strict';

// autoplayguard.js —— HTMLMediaElement / Web Audio 自动播放策略裁决内核。
//
// 威胁模型（把自动播放当作安全/打扰与资源滥用面，而非仅体验问题）：
//   1. 带声自动播放视频被用于强制广告、惊吓/钓鱼语音（"你的电脑中毒，请拨打…"）社工；
//   2. 页面一加载就 new Audio().play() 或 WebAudio  resume()，无手势出声；
//   3. 大量静音 autoplay 视频 + createMediaElementSource 做后台解码，耗 CPU/GPU/电量，
//      并借 WebAudio 分析做音频指纹；
//   4. play() 在被拒后高频重试（autoplay 重试风暴）弹权限/占资源；
//   5. requestPictureInPicture / setSinkId 借自动播放链做外设枚举（输出设备指纹）；
//   6. 后台标签仍持续播放音视频做隐蔽跟踪/保活。
//
// 纯逻辑：综合手势、媒体参与度（MEI 风格白名单）、静音、后台、重试频控裁决 play/resume。

const AP_DENY = 'deny';
const AP_ALLOW = 'allow';
const AP_MUTED_ONLY = 'muted-only'; // 仅允许静音播放

const AP_REASON = Object.freeze({
  BAD_ORIGIN: 'ap-bad-origin',
  BLOCKED_ORIGIN: 'ap-blocked-origin',
  NO_ENGAGEMENT_AUDIO: 'ap-no-engagement-audio',
  BACKGROUND_AUDIO: 'ap-background-audio',
  PLAY_RETRY_FLOOD: 'ap-play-retry-flood',
  TOO_MANY_CONCURRENT_MEDIA: 'ap-too-many-concurrent-media',
  WEBAUDIO_RESUME_NO_GESTURE: 'ap-webaudio-resume-no-gesture',
  SINKID_DEVICE_ENUM: 'ap-sinkid-device-enum',
});

function defaultAutoplayPolicy() {
  return {
    // 无用户手势/参与度时，带声自动播放是否直接降级为静音。
    downgradeUnaudibleToMuted: true,
    denyBackgroundAudio: true,
    allowMutedAutoplay: true,
    playRetryMinIntervalMs: 800,
    maxPlayRetries: 3,
    maxConcurrentPlayingMedia: 6,
    allowWebAudioSuspendOnlyWithoutGesture: true, // 无手势只允许 suspend，不允许 resume
    allowSetSinkIdPick: false,
    // 高参与度来源（用户常在此站播放媒体）可带声自动播放。
    highEngagementOrigins: [],
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

class AutoplayGuard {
  constructor(policy) {
    this.policy = policy || defaultAutoplayPolicy();
    this.retryCount = new Map();
    this.lastRetry = new Map();
    this.playingCount = new Map();
  }

  isHighEngagement(origin) {
    const full = originKey(origin); // https://host 形式
    const schemeIdx = full.indexOf('://');
    const host = schemeIdx >= 0 ? full.slice(schemeIdx + 3) : full;
    return this.policy.highEngagementOrigins.some((h) => {
      const hv = h.indexOf('://') >= 0 ? h.slice(h.indexOf('://') + 3) : h;
      return host === hv || host.endsWith('.' + hv);
    });
  }

  // decidePlay 裁决 media.play()。
  // ctx: {origin, blocked, hasUserGesture, isBackground, now}
  // media: {muted, hasAudioTrack, isVideo}
  decidePlay(ctx, media) {
    const pol = this.policy;
    const key = originKey(ctx && ctx.origin);
    if (!key) return { decision: AP_DENY, reason: AP_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { decision: AP_DENY, reason: AP_REASON.BLOCKED_ORIGIN };
    const now = ctx.now || 0;
    const muted = !!(media && media.muted);
    const hasAudio = !media || media.hasAudioTrack !== false;

    // 并发媒体数上限（静音也算，防后台解码滥用）。
    if ((this.playingCount.get(key) || 0) >= pol.maxConcurrentPlayingMedia) {
      return { decision: AP_DENY, reason: AP_REASON.TOO_MANY_CONCURRENT_MEDIA };
    }

    // 出声路径。
    if (hasAudio && !muted) {
      if (pol.denyBackgroundAudio && ctx.isBackground === true) {
        return { decision: AP_DENY, reason: AP_REASON.BACKGROUND_AUDIO };
      }
      const engaged = ctx.hasUserGesture === true || this.isHighEngagement(ctx.origin);
      if (!engaged) {
        if (pol.downgradeUnaudibleToMuted && pol.allowMutedAutoplay) {
          return { decision: AP_MUTED_ONLY, reason: AP_REASON.NO_ENGAGEMENT_AUDIO };
        }
        return { decision: AP_DENY, reason: AP_REASON.NO_ENGAGEMENT_AUDIO };
      }
    } else if (!pol.allowMutedAutoplay && ctx.hasUserGesture !== true) {
      return { decision: AP_DENY, reason: AP_REASON.NO_ENGAGEMENT_AUDIO };
    }

    this.playingCount.set(key, (this.playingCount.get(key) || 0) + 1);
    return { decision: AP_ALLOW, reason: '' };
  }

  noteEnded(origin) {
    const key = originKey(origin);
    this.playingCount.set(key, Math.max(0, (this.playingCount.get(key) || 1) - 1));
  }

  // notePlayRejected 在 play() 被拒/失败时记录重试，裁决是否还允许再试。
  notePlayRejected(origin, now) {
    const pol = this.policy;
    const key = originKey(origin);
    const n = (this.retryCount.get(key) || 0) + 1;
    this.retryCount.set(key, n);
    if (n > pol.maxPlayRetries) return { retry: false, reason: AP_REASON.PLAY_RETRY_FLOOD };
    if (this.lastRetry.has(key) && now - this.lastRetry.get(key) < pol.playRetryMinIntervalMs) {
      return { retry: false, reason: AP_REASON.PLAY_RETRY_FLOOD };
    }
    this.lastRetry.set(key, now);
    return { retry: true, reason: '' };
  }

  // decideAudioContextResume 裁决 AudioContext.resume()。
  decideAudioContextResume(ctx) {
    if (!originKey(ctx && ctx.origin)) return { allowed: false, reason: AP_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { allowed: false, reason: AP_REASON.BLOCKED_ORIGIN };
    if (ctx.hasUserGesture !== true && !this.isHighEngagement(ctx.origin)) {
      return { allowed: false, reason: AP_REASON.WEBAUDIO_RESUME_NO_GESTURE };
    }
    return { allowed: true, reason: '' };
  }

  // decideSetSinkId 裁决 HTMLMediaElement.setSinkId（输出设备选择/枚举）。
  decideSetSinkId(ctx) {
    if (!originKey(ctx && ctx.origin)) return { allowed: false, reason: AP_REASON.BAD_ORIGIN };
    if (!this.policy.allowSetSinkIdPick) {
      return { allowed: false, reason: AP_REASON.SINKID_DEVICE_ENUM };
    }
    if (ctx.hasUserGesture !== true) return { allowed: false, reason: AP_REASON.SINKID_DEVICE_ENUM };
    return { allowed: true, reason: '' };
  }
}

module.exports = {
  AP_ALLOW, AP_DENY, AP_MUTED_ONLY, AP_REASON,
  defaultAutoplayPolicy, originKey, AutoplayGuard,
};
