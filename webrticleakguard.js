'use strict'

// webrticleakguard.js —— WebRTC IP 泄露（mDNS/真实 IP 暴露）与 STUN 策略守卫。
//
// 威胁模型（隐私）：
//   页面用 RTCPeerConnection 收集 ICE candidate 时，默认会向 STUN 服务器暴露本机公网 IP，
//   在未用 mDNS 混淆时还会泄露内网真实 IP（192.168.x.x），被用于指纹追踪/内网测绘：
//     - iceServers 含任意外部 STUN/TURN（把 IP 发往第三方）；
//     - iceTransportPolicy/候选策略允许 host candidate 直接暴露内网 IP；
//     - TURN 凭据写死在前端；
//     - 在非 https 上下文使用媒体能力。
//   本模块审计 RTCPeerConnection 配置与收集到的 candidate。纯字符判定，不使用正则。

const WR_REASON = Object.freeze({
  EXTERNAL_STUN: 'webrtc-config-uses-thirdparty-stun-server',
  TURN_CREDENTIAL_EMBEDDED: 'webrtc-turn-credential-embedded-in-client-config',
  PRIVATE_IP_CANDIDATE: 'ice-candidate-reveals-private-ip-address',
  NON_SECURE_CONTEXT: 'webrtc-used-outside-secure-context',
  HOST_CANDIDATE_POLICY: 'webrtc-policy-allows-raw-host-candidates'
})

const { ilClassifyV4 } = require('./ipliteralguard.js')

const LEAK_CLASSES = new Set(['private', 'loopback', 'linklocal'])

function wrLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

function wrHost (url) {
  let s = String(url)
  const at = s.lastIndexOf('@')
  if (at >= 0) s = s.slice(at + 1)
  // 去掉 scheme：stun:host / turns://host / turn:user@host（userinfo 已在上面剥离）。
  const schemeColon = s.indexOf(':')
  if (schemeColon >= 0) {
    const after = s.slice(schemeColon + 1, schemeColon + 3)
    if (after === '//') s = s.slice(schemeColon + 3)
    else s = s.slice(schemeColon + 1)
  }
  let rest = s
  if (rest[0] === '[') {
    const c = rest.indexOf(']')
    return c >= 0 ? wrLower(rest.slice(1, c)) : wrLower(rest)
  }
  const colon = rest.indexOf(':')
  if (colon >= 0) rest = rest.slice(0, colon)
  return wrLower(rest)
}

// 手写扫描 candidate 中的 a.b.c.d（不用正则），交给 ipliteralguard 分类。
function wrScanV4 (s) {
  const out = []
  let i = 0
  while (i < s.length) {
    const start = i
    let octets = 0
    let valid = true
    let digits = 0
    while (i < s.length) {
      const c = s[i]
      if (c >= '0' && c <= '9') {
        digits++
        i++
      } else if (c === '.') {
        if (digits === 0 || digits > 3) { valid = false; break }
        octets++
        digits = 0
        i++
      } else {
        break
      }
    }
    const token = s.slice(start, i)
    if (valid && octets === 3 && digits >= 1 && digits <= 3) out.push(token)
    if (i === start) i++
  }
  return out
}

class WebRtcLeakGuard {
  // allowedStunHosts：允许的自有 STUN 主机白名单（空表示不允许任何外部 STUN）。
  constructor (allowedStunHosts) {
    this.allow = new Set((allowedStunHosts || []).map(wrLower))
  }

  // config: { secureContext, iceServers:[{urls,username,credential}], iceTransportPolicy, hostCandidatePolicy }
  evaluateConfig (config) {
    const c = config || {}
    const findings = []
    if (c.secureContext === false) findings.push({ reason: WR_REASON.NON_SECURE_CONTEXT })
    for (const srv of c.iceServers || []) {
      const urls = Array.isArray(srv.urls) ? srv.urls : [srv.urls]
      for (const u of urls) {
        const url = String(u || '')
        const kind = wrLower(url.slice(0, url.indexOf(':')))
        const host = wrHost(url)
        if ((kind === 'stun' || kind === 'turn' || kind === 'turns') &&
            !(host && this.allow.has(host))) {
          findings.push({ reason: WR_REASON.EXTERNAL_STUN, detail: host })
        }
        if (kind === 'turn' || kind === 'turns') {
          if (srv.credential !== undefined && srv.credential !== null) {
            findings.push({ reason: WR_REASON.TURN_CREDENTIAL_EMBEDDED })
          }
        }
      }
    }
    const hostPolicy = wrLower(String(c.hostCandidatePolicy || ''))
    if (hostPolicy === '' || hostPolicy === 'host' || hostPolicy === 'all') {
      if (c.mdnsObfuscation !== true) findings.push({ reason: WR_REASON.HOST_CANDIDATE_POLICY })
    }
    return { safe: findings.length === 0, findings: findings }
  }

  // 审计一条收集到的 ICE candidate 文本是否泄露内网/环回/链路本地 IP。
  evaluateCandidate (candidate) {
    const s = String(candidate || '')
    const findings = []
    for (const ip of wrScanV4(s)) {
      if (LEAK_CLASSES.has(ilClassifyV4(ip))) {
        findings.push({ reason: WR_REASON.PRIVATE_IP_CANDIDATE, detail: ip })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  WR_REASON: WR_REASON,
  wrScanV4: wrScanV4,
  WebRtcLeakGuard: WebRtcLeakGuard
})
