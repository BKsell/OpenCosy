'use strict';

// pointerlockguard.js —— Pointer Lock（鼠标锁定）调用闸门。
//
// navigator.requestPointerLock 会把鼠标永久困在页面里，用于 FPS。恶意页可以
// 在用户不知情时锁定鼠标并劫持 Esc 退出流程（Chrome 89+ 后用户手势要求收紧）。
// 这里把“这次 requestPointerLock 该不该放行”收敛成纯函数。

// decidePointerLock 入参：
//   hasUserGesture 布尔
//   isSecureContext 布尔
//   targetUrl      字符串（当前页 URL，用于 about: 内部页判定）
// 返回 { action:'allow'|'block', reason }
function decidePointerLock(hasUserGesture, isSecureContext, targetUrl) {
  if (!isSecureContext) {
    return { action: 'block', reason: 'insecure-context' };
  }
  if (!hasUserGesture) {
    return { action: 'block', reason: 'no-user-gesture' };
  }
  const u = String(targetUrl || '');
  if (u.startsWith('about:') || u.startsWith('chrome:') || u.startsWith('devtools:')) {
    return { action: 'block', reason: 'internal-page' };
  }
  return { action: 'allow', reason: 'ok' };
}

// shouldShowExitHint 锁定成功后是否给用户常驻“按 Esc 退出”提示。
// 现代浏览器自己会显示退出提示；这里是壳自己加的二次提示策略。
function shouldShowExitHint(secondsSinceLock) {
  // 锁定后前 3 秒常驻提示，之后淡出。
  return Number(secondsSinceLock || 0) < 3;
}

module.exports = {
  decidePointerLock,
  shouldShowExitHint,
};
