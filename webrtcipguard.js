'use strict';

// webrtcipguard.js —— WebRTC 本地 IP 泄露闸门。
//
// STUN 协商会把本机内网 IPv4/IPv6 候选暴露给远端对端，即使页面本身是 HTTPS。
// 广告/追踪脚本用它做指纹和内网探测。这里把“这次 WebRTC 连接该不该暴露本地
// 候选”收敛成纯函数。

// decideWebRTC 入参：
//   hasUserGesture 布尔（getUserMedia/RTCPeerConnection 应由用户手势触发）
//   isSecureContext 布尔
//   policy         字符串：'allow' | 'block-local-candidates' | 'block-all'
// 返回 { action:'allow'|'block', localCandidates:'allow'|'muted', reason }
function decideWebRTC(opts) {
  const o = opts || {};
  if (!o.isSecureContext) {
    return { action: 'block', localCandidates: 'muted', reason: 'insecure-context' };
  }
  const policy = String(o.policy || 'block-local-candidates');
  if (policy === 'block-all') {
    return { action: 'block', localCandidates: 'muted', reason: 'policy-block-all' };
  }
  if (!o.hasUserGesture && policy !== 'allow') {
    return { action: 'block', localCandidates: 'muted', reason: 'no-user-gesture' };
  }
  if (policy === 'block-local-candidates') {
    // 允许连接，但把 mDNS/.local 候选以外的本地地址隐藏。
    return { action: 'allow', localCandidates: 'muted', reason: 'mute-local' };
  }
  return { action: 'allow', localCandidates: 'allow', reason: 'allow' };
}

// isLocalCandidateAddress 粗判一个 ICE 候选是不是内网地址。
function isLocalCandidateAddress(addr) {
  const a = String(addr || '').toLowerCase();
  if (a.startsWith('10.') || a.startsWith('192.168.')) return true;
  if (a.startsWith('172.')) {
    const second = Number(a.split('.')[1]);
    if (second >= 16 && second <= 31) return true;
  }
  if (a === '127.0.0.1' || a === '::1' || a.startsWith('fe80:')) return true;
  if (a.endsWith('.local')) return true;
  return false;
}

module.exports = {
  decideWebRTC,
  isLocalCandidateAddress,
  filterLocalCandidates,
};

// filterLocalCandidates 从 ICE 候选字符串列表里剔除本地内网候选，
// 返回 mDNS 替换后的新列表（调用方把 local 候选换成 x.local 形式）。
function filterLocalCandidates(candidates) {
  const out = [];
  for (const c of Array.isArray(candidates) ? candidates : []) {
    const s = String(c || '');
    const m = s.match(/(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:]+\])/i);
    if (m && isLocalCandidateAddress(m[1])) {
      continue;
    }
    out.push(s);
  }
  return out;
}
