'use strict';

// offlineerrorpage.js —— 离线/网络错误页分类。
//
// 网络挂了、DNS 解析失败、证书错误、连接被重置，应该给用户不同的提示，
// 不能所有错误都塞一句"无法访问"。这里把错误码收敛成分类纯函数。

// classifyNetworkError 入参：
//   errorCode  Chromium net error 或自定义字符串，如 '-106'、'ERR_NAME_NOT_RESOLVED'
//   isOffline  布尔：navigator.onLine
// 返回 { category, title, retryable }
function classifyNetworkError(opts) {
  const o = opts || {};
  const code = String(o.errorCode || '').toUpperCase();
  if (o.isOffline) {
    return { category: 'offline', title: '没有网络连接', retryable: true };
  }
  if (code.includes('NAME_NOT_RESOLVED') || code === '-105') {
    return { category: 'dns', title: '找不到服务器地址', retryable: true };
  }
  if (code.includes('CERT') || code === '-200' || code === '-201' || code === '-107') {
    return { category: 'cert', title: '证书不受信任', retryable: false };
  }
  if (code.includes('CONNECTION_RESET') || code === '-101') {
    return { category: 'reset', title: '连接被重置', retryable: true };
  }
  if (code.includes('CONNECTION_REFUSED') || code === '-102') {
    return { category: 'refused', title: '连接被拒绝', retryable: true };
  }
  if (code.includes('TIMED_OUT') || code === '-118') {
    return { category: 'timeout', title: '连接超时', retryable: true };
  }
  if (code.includes('BLOCKED') || code.includes('ADBLOCK')) {
    return { category: 'blocked', title: '内容被拦截', retryable: false };
  }
  return { category: 'unknown', title: '无法访问此网站', retryable: true };
}

// isRetryableAfterBackoff 是否适合自动重试（指数退避）。
function isRetryableAfterBackoff(category) {
  return ['offline', 'dns', 'reset', 'timeout'].includes(category);
}

module.exports = {
  classifyNetworkError,
  isRetryableAfterBackoff,
};
