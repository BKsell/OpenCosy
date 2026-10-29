'use strict';

// pictureinpictureguard.js —— Picture-in-Picture 窗口策略。
//
// PiP 窗口独立于标签页存活，导航/关闭标签后音频画面还在继续，容易被恶意
// 页面用来"隐藏后台窃听"或在用户离开后继续播放。这里把"这次 PiP 请求该不该
// 批"收敛成纯函数。

// decidePip 入参：
//   hasUserGesture  布尔
//   isSecureContext 布尔
//   origin          调用方 origin
//   userTrusted     布尔（用户在站点权限里显式允许过）
//   videoDurationSec 视频长度（长视频更可能被滥用）
// 返回 { action:'allow'|'deny', reason }
function decidePip(opts) {
  const o = opts || {};
  if (!o.isSecureContext) {
    return { action: 'deny', reason: 'insecure-context' };
  }
  if (!o.hasUserGesture) {
    return { action: 'deny', reason: 'no-user-gesture' };
  }
  const dur = Number(o.videoDurationSec || 0);
  if (dur > 0 && dur < 1) {
    // 极短视频开 PiP 几乎一定是脚本误触发/嗅探。
    return { action: 'deny', reason: 'video-too-short' };
  }
  if (!o.userTrusted && dur > 4 * 60 * 60) {
    // 未信任源且视频超长，提示用户。
    return { action: 'deny', reason: 'long-video-needs-consent' };
  }
  return { action: 'allow', reason: 'ok' };
}

// shouldAutoClosePipOnTabClose 标签页关闭时是否自动关 PiP。
// 默认关；用户在该 origin 选过"允许后台 PiP"才保留。
function shouldAutoClosePipOnTabClose(userTrusted) {
  return !userTrusted;
}

module.exports = {
  decidePip,
  shouldAutoClosePipOnTabClose,
};
