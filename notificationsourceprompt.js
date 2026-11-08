'use strict';

// notificationsourceprompt.js —— Web Notification 触发时的源确认策略。
//
// 现代浏览器在弹通知前已经有权限提示；但通知内容本身可能带外链接。这里把
// “这次通知该不该弹、要不要在标题里带上源 origin”收敛成纯函数。

// decideNotificationDisplay 入参：
//   permission      'granted' | 'denied' | 'default'
//   hasUserGesture  布尔（首次调用 Notification.requestPermission 时）
//   origin          调用方页面 origin
//   titleLength     通知标题长度
// 返回 { action:'show'|'hide', annotateOrigin:boolean, reason }
function decideNotificationDisplay(opts) {
  const o = opts || {};
  const perm = String(o.permission || 'default');
  if (perm === 'denied') {
    return { action: 'hide', annotateOrigin: false, reason: 'denied' };
  }
  if (perm === 'default' && !o.hasUserGesture) {
    return { action: 'hide', annotateOrigin: false, reason: 'need-gesture-for-prompt' };
  }
  const len = Number(o.titleLength || 0);
  if (len > 200) {
    return { action: 'hide', annotateOrigin: false, reason: 'title-too-long' };
  }
  // 跨源通知（非用户手动授权过的站点）强制带源标注。
  const annotate = !o.userTrustedOrigin;
  return { action: 'show', annotateOrigin: annotate, reason: 'ok' };
}

// shouldSuppressAutoshowOnRepeated 短时间内同 origin 重复通知折叠。
function shouldSuppressRepeated(countInWindow) {
  return Number(countInWindow || 0) >= 5;
}

module.exports = {
  decideNotificationDisplay,
  shouldSuppressRepeated,
};
