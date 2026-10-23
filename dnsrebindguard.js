'use strict'

// dnsrebindguard.js —— DNS 应答的重绑定（rebinding）与范围混合守卫。
//
// 威胁模型：
//   浏览器/主进程连接下载、认证主机时若信任单次 DNS 结果直接连，攻击者控制的权威 DNS 可在两次
//   解析间切换地址：第一次给公网 IP 通过校验，第二次给 127.0.0.1/169.254.169.254/内网 IP，
//   让带凭证的请求实际打到内网或本机（DNS rebinding）。
//   本模块审计"一次解析的地址集合"以及"校验地址与建连地址是否漂移"：
//     - 同一名字的记录跨 public/private/loopback/linklocal 范围（mixed-scope）；
//     - 出现环回/链路本地/私网地址；
//     - TTL 0/1s 且集合跨范围（快速重绑定特征）；
//     - 校验时 IP 与真正建连时 IP 不一致（pin 漂移）。
//   地址分类复用 ipliteralguard，不做真实网络调用，不使用正则。

const { ilClassifyV4 } = require('./ipliteralguard.js')

const DR_REASON = Object.freeze({
  MIXED_SCOPE: 'dns-answer-set-mixes-public-and-internal-scopes',
  INTERNAL_RECORD: 'dns-answer-contains-loopback-private-or-linklocal',
  SUSPICIOUS_TTL: 'dns-answer-ttl-zero-or-one-with-mixed-records',
  PIN_DRIFT: 'dns-rebind-verify-address-differs-from-connect-address'
})

const INTERNAL_CLASSES = new Set(['loopback', 'private', 'linklocal'])

class DnsRebindGuard {
  constructor () {
    this.pinned = new Map()
  }

  // records: [{ ip: '1.2.3.4', ttl: 60 }]
  evaluateAnswerSet (records) {
    const findings = []
    const scopes = new Set()
    let internal = false
    for (const rec of records) {
      const cls = ilClassifyV4(rec.ip)
      scopes.add(cls)
      if (INTERNAL_CLASSES.has(cls)) {
        internal = true
        findings.push({ reason: DR_REASON.INTERNAL_RECORD, detail: rec.ip })
      }
    }
    const publicScope = scopes.has('public')
    if (internal && (publicScope || scopes.size > 1)) {
      findings.push({ reason: DR_REASON.MIXED_SCOPE })
    }
    if (scopes.size > 1) {
      for (const rec of records) {
        if (typeof rec.ttl === 'number' && rec.ttl >= 0 && rec.ttl <= 1) {
          findings.push({ reason: DR_REASON.SUSPICIOUS_TTL, detail: String(rec.ttl) })
          break
        }
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }

  // 记录主机名在"安全校验那次解析"时使用的地址。
  pin (host, verifiedIP) {
    this.pinned.set(host, verifiedIP)
  }

  // 建连前校验实际解析地址是否仍等于 pinned 地址。
  verifyConnect (host, connectIP) {
    const verified = this.pinned.get(host)
    if (verified === undefined) {
      return { safe: false, findings: [{ reason: DR_REASON.PIN_DRIFT, detail: 'no-pin' }] }
    }
    if (verified !== connectIP) {
      return {
        safe: false,
        findings: [{ reason: DR_REASON.PIN_DRIFT, detail: verified + '->' + connectIP }]
      }
    }
    return { safe: true, findings: [] }
  }
}

module.exports = Object.freeze({
  DR_REASON: DR_REASON,
  DnsRebindGuard: DnsRebindGuard
})
