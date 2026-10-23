'use strict'

// rtcsdpttokendirectoryguard.js —— WebRTC SDP/ICE 风险令牌目录。
//
// 威胁模型：
//   SDP 中 mDNS 混淆、srTP 关闭、ICE 候选泄露内网地址、data channel 需复核。纯字符查表，不用正则。

const RTP_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const RTP_BLOCK = Object.freeze([
  'a=ice-ufrag',
  'a=ice-pwd',
  'a=fingerprint',
  'a=candidate',
  'a=rtcp-mux',
  'a=ssrc',
  'a=ssrc-group',
  'a=mid',
  'a=setup',
  'a=tls-id',
  'a=setup:actpass',
  'c=IN',
  'o=',
])

const RTP_WARN = Object.freeze([
  'm=application',
  'm=audio',
  'm=video',
  'a=sctp-port',
  'a=max-message-size',
  'a=sctpmap',
  'a=sendrecv',
  'a=sendonly',
  'a=recvonly',
  'a=inactive',
  'a=extmap',
  'a=rtpmap',
  'a=rtcp-fb',
  'a=fmtp',
  'a=ice-options',
  'a=end-of-candidates',
  'a=candidate:host',
  'a=candidate:srflx',
  'a=candidate:relay',
  'a=candidate:prflx',
  'mdns',
  '.local',
  'ICE-TCP',
  'TURN',
  'STUN',
  'DTLS',
  'SRTP',
  'RTP',
  'RTCP',
  'SDP',
])

const RTP_ALLOW = Object.freeze([
  'v=0',
  't=0 0',
  'm=',
  'a=group',
  'a=bundle-only',
  'a=crypto',
  'a=ice-lite',
  'SAVPF',
  'UDP',
  'TCP',
  'TLS',
  'SCTP',
  'DATA',
])

function RTPLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function RTPIn (list, v) {
  for (const x of list) { if (RTPLower(x) === v) return true }
  return false
}

function RTPClassify (tok) {
  const v = RTPLower(String(tok == null ? '' : tok).trim())
  if (RTPIn(RTP_BLOCK, v)) return RTP_CLASS.BLOCK
  if (RTPIn(RTP_WARN, v)) return RTP_CLASS.WARN
  if (RTPIn(RTP_ALLOW, v)) return RTP_CLASS.ALLOW
  return RTP_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  RTP_CLASS: RTP_CLASS,
  RTP_BLOCK: RTP_BLOCK,
  RTP_WARN: RTP_WARN,
  RTP_ALLOW: RTP_ALLOW,
  RTPClassify: RTPClassify
})
