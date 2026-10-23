'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WebRtcLeakGuard, WR_REASON, wrScanV4 } = require('./webrticleakguard.js')

test('scan extracts ipv4 tokens', () => {
  const toks = wrScanV4('candidate 192.168.5.10 typ host and 8.8.8.8')
  assert.deepEqual(toks, ['192.168.5.10', '8.8.8.8'])
})

test('private ip candidate flagged', () => {
  const g = new WebRtcLeakGuard()
  assert.ok(!g.evaluateCandidate('candidate 192.168.1.20 typ host').safe)
  assert.ok(g.evaluateCandidate('candidate 8.8.8.8 typ srflx').safe)
})

test('loopback and linklocal candidate flagged', () => {
  const g = new WebRtcLeakGuard()
  assert.ok(!g.evaluateCandidate('a 127.0.0.1').safe)
  assert.ok(!g.evaluateCandidate('a 169.254.1.1').safe)
})

test('172.16-31 private detected but 172.200 public not', () => {
  const g = new WebRtcLeakGuard()
  assert.ok(!g.evaluateCandidate('a 172.16.0.1').safe)
  assert.ok(g.evaluateCandidate('a 172.200.0.1').safe)
})

test('thirdparty stun flagged', () => {
  const g = new WebRtcLeakGuard(['stun.own.test'])
  const r = g.evaluateConfig({ secureContext: true, mdnsObfuscation: true, iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] })
  assert.ok(r.findings.some((f) => f.reason === WR_REASON.EXTERNAL_STUN))
})

test('allowed own stun safe with mdns', () => {
  const g = new WebRtcLeakGuard(['stun.own.test'])
  const r = g.evaluateConfig({ secureContext: true, mdnsObfuscation: true, iceServers: [{ urls: 'stun:stun.own.test:3478' }] })
  assert.equal(r.safe, true)
})

test('turn credential embedded flagged', () => {
  const g = new WebRtcLeakGuard(['turn.own.test'])
  const r = g.evaluateConfig({
    secureContext: true, mdnsObfuscation: true,
    iceServers: [{ urls: 'turn:turn.own.test:443', username: 'u', credential: 'secret' }]
  })
  assert.ok(r.findings.some((f) => f.reason === WR_REASON.TURN_CREDENTIAL_EMBEDDED))
})

test('raw host candidates without mdns flagged', () => {
  const g = new WebRtcLeakGuard()
  const r = g.evaluateConfig({ secureContext: true, iceServers: [], hostCandidatePolicy: 'all' })
  assert.ok(r.findings.some((f) => f.reason === WR_REASON.HOST_CANDIDATE_POLICY))
})

test('non-secure context flagged', () => {
  const g = new WebRtcLeakGuard()
  assert.ok(g.evaluateConfig({ secureContext: false, mdnsObfuscation: true }).findings.some((f) => f.reason === WR_REASON.NON_SECURE_CONTEXT))
})
