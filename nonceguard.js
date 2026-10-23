'use strict'

// nonceguard.js —— CSP nonce 的生成强度、一次性使用与生命周期守卫。
//
// 威胁模型：
//   CSP 'nonce-xxx' 用来白名单可信内联脚本。nonce 实现不当会被猜/重用：
//     - 长度/熵不足（短、可预测、Math.random 时间戳拼出来的）；
//     - 同一 nonce 被多个脚本或多次响应复用（一个 XSS 即可在其它地方复用）；
//     - nonce 出现在非 HTML 上下文（被缓存、写进 URL/日志）；
//     - 用过的 nonce 未失效。
//   本模块负责生成高熵 nonce、记录一次性消费、审计外部给入 nonce 的强度。纯判定，不使用正则。

const NC_REASON = Object.freeze({
  TOO_SHORT: 'csp-nonce-too-short',
  LOW_ENTROPY: 'csp-nonce-appears-low-entropy',
  REUSE: 'csp-nonce-reused-across-responses',
  CONSUMED_TWICE: 'csp-nonce-consumed-more-than-once',
  LEAKED_IN_URL: 'csp-nonce-appears-in-url-or-query'
})

const MIN_NONCE_LEN = 22 // 约 128 位 base64

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

class NonceGuard {
  constructor (random) {
    this.random = random || null
    this.issued = new Set()
    this.consumed = new Set()
  }

  // 优先使用注入的随机源（便于测试）；生产应注入 crypto 随机字节。
  generate () {
    let out = ''
    const bytes = this.random
      ? this.random(MIN_NONCE_LEN)
      : ncDefaultBytes(MIN_NONCE_LEN)
    for (let i = 0; i < MIN_NONCE_LEN; i++) {
      out += ALPHABET[bytes[i] & 63]
    }
    this.issued.add(out)
    return out
  }

  // 审计一个将出现在 CSP 里的 nonce 是否够强、是否跨响应复用。
  audit (nonce, context) {
    const n = String(nonce || '')
    const findings = []
    if (n.length < MIN_NONCE_LEN) findings.push({ reason: NC_REASON.TOO_SHORT })
    if (ncLowEntropy(n)) findings.push({ reason: NC_REASON.LOW_ENTROPY })
    if (this.issued.has(n) && context !== 'current-response') {
      findings.push({ reason: NC_REASON.REUSE })
    }
    this.issued.add(n)
    if (context === 'url' || context === 'query' || context === 'log') {
      findings.push({ reason: NC_REASON.LEAKED_IN_URL, detail: context })
    }
    return { safe: findings.length === 0, findings: findings }
  }

  // 脚本真正用 nonce 执行时调用，保证一个 nonce 只消费一次。
  consume (nonce) {
    const n = String(nonce || '')
    if (this.consumed.has(n)) {
      return { safe: false, findings: [{ reason: NC_REASON.CONSUMED_TWICE }] }
    }
    this.consumed.add(n)
    return { safe: true, findings: [] }
  }
}

function ncDefaultBytes (n) {
  // 无注入随机源时的兜底；真实环境应注入 crypto.getRandomValues。
  const out = new Array(n)
  for (let i = 0; i < n; i++) out[i] = (Math.random() * 256) | 0
  return out
}

// 粗略低熵判定：字符种类过少或长段重复。
function ncLowEntropy (s) {
  if (s.length < MIN_NONCE_LEN) return false
  const seen = new Set()
  for (let i = 0; i < s.length; i++) seen.add(s[i])
  if (seen.size < 12) return true
  let run = 1
  for (let i = 1; i < s.length; i++) {
    if (s[i] === s[i - 1]) {
      run++
      if (run >= 6) return true
    } else {
      run = 1
    }
  }
  return false
}

module.exports = Object.freeze({
  NC_REASON: NC_REASON,
  MIN_NONCE_LEN: MIN_NONCE_LEN,
  NonceGuard: NonceGuard,
  ncLowEntropy: ncLowEntropy
})
