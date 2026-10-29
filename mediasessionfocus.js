'use strict';

// mediasessionfocus.js —— 硬件媒体键（播放/暂停/上一首/下一首）焦点路由。
//
// 现代浏览器要求：媒体键只发给“当前正在发声”的标签，且后台标签不能抢键。
// 恶意页可以在后台抢 MediaSessionAction 劫持用户的耳机键。这里把“这次媒体键
// 该不该发给这个标签”收敛成纯函数。

// decideMediaKeyDispatch 入参：
//   audible       布尔，标签当前是否在发声
//   focusedTab    布尔，标签是否为前台焦点
//   hasMediaSessionHandler 布尔，页面是否注册了 MediaSessionActionHandler
//   backgroundKeyHijackAllowed 布尔，用户是否手动允许后台抢键（默认 false）
// 返回 { action:'dispatch'|'drop', reason }
function decideMediaKeyDispatch(opts) {
  const o = opts || {};
  if (!o.hasMediaSessionHandler) {
    return { action: 'drop', reason: 'no-handler' };
  }
  if (o.audible) {
    // 正在发声的标签（哪怕在后台）始终可以响应媒体键，这是音乐播放器的预期行为。
    return { action: 'dispatch', reason: 'audible' };
  }
  if (!o.audible && o.focusedTab) {
    return { action: 'dispatch', reason: 'focused-page' };
  }
  if (!o.audible && !o.focusedTab && o.backgroundKeyHijackAllowed) {
    return { action: 'dispatch', reason: 'background-user-allowed' };
  }
  return { action: 'drop', reason: 'background-hijack-blocked' };
}

// isMediaSessionActionKnown 是否是规范里的动作名。
const KNOWN_ACTIONS = new Set([
  'play', 'pause', 'seekbackward', 'seekforward',
  'previoustrack', 'nexttrack', 'seekto', 'stop',
]);

function isMediaSessionActionKnown(action) {
  return KNOWN_ACTIONS.has(String(action || ''));
}

module.exports = {
  KNOWN_ACTIONS,
  decideMediaKeyDispatch,
  isMediaSessionActionKnown,
};
