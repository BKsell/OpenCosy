'use strict'

// ipliteralguard.js —— 主机位"替代 IP 编码"归一化守卫。
//
// 威胁模型：
//   只对标准点分十进制（127.0.0.1）做私网/环回判断会被等价写法绕过，连接最终仍落到内网/本机：
//     - 十进制整数 http://2130706433/ == 127.0.0.1；
//     - 八进制 0177.0.0.1、十六进制 0x7f.0.0.1 / 0x7f000001、混合进制；
//     - IPv6 环回 ::1、IPv4 映射 ::ffff:127.0.0.1、IPv4 兼容 ::127.0.0.1、方括号 [::1]。
//   本模块把主机位归一为点分 IPv4 并分类 public/private/loopback/linklocal，标记非规范编码。
//   纯字符解析，不做 DNS，不使用正则。

const IL_REASON = Object.freeze({
  AMBIGUOUS_ENCODING: 'ip-literal-non-canonical-encoding',
  IPV6_LOOPBACK: 'ip-literal-ipv6-loopback',
  IPV6_MAPPED_INTERNAL: 'ip-literal-ipv6-mapped-ipv4-internal'
})

function ilAllDigits (s) {
  if (s.length === 0) return false
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 48 || c > 57) return false
  }
  return true
}

function ilClassifyV4 (ip) {
  const p = ip.split('.')
  if (p.length !== 4) return 'invalid'
  const n = []
  for (const seg of p) {
    if (!ilAllDigits(seg)) return 'invalid'
    const v = Number(seg)
    if (!Number.isInteger(v) || v < 0 || v > 255) return 'invalid'
    n.push(v)
  }
  if (n[0] === 127) return 'loopback'
  if (n[0] === 10) return 'private'
  if (n[0] === 172 && n[1] >= 16 && n[1] <= 31) return 'private'
  if (n[0] === 192 && n[1] === 168) return 'private'
  if (n[0] === 169 && n[1] === 254) return 'linklocal'
  if (n[0] === 0) return 'loopback'
  return 'public'
}

function ilParseRadix (s, base) {
  let v = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    let d = -1
    if (c >= 48 && c <= 57) d = c - 48
    else if (base === 16 && c >= 97 && c <= 102) d = c - 97 + 10
    else if (base === 16 && c >= 65 && c <= 70) d = c - 65 + 10
    if (d < 0 || d >= base) return null
    v = v * base + d
    if (v > 0xFFFFFFFF) return null
  }
  return v
}

function ilParseSegment (seg) {
  if (seg.length === 0) return null
  if (seg.length >= 2 && (seg.slice(0, 2) === '0x' || seg.slice(0, 2) === '0X')) {
    return { value: ilParseRadix(seg.slice(2), 16), nonCanonical: true }
  }
  if (seg.length >= 2 && seg[0] === '0') {
    const v = ilParseRadix(seg, 8)
    if (v !== null) return { value: v, nonCanonical: true }
  }
  const v = ilParseRadix(seg, 10)
  if (v === null) return null
  return { value: v, nonCanonical: false }
}

class IpLiteralGuard {
  // host 为去端口后的主机位（可带方括号）。
  normalize (host) {
    let h = String(host)
    if (h.length >= 2 && h[0] === '[' && h[h.length - 1] === ']') h = h.slice(1, -1)

    if (h.indexOf(':') >= 0) return this.classifyV6(h)

    const segs = h.split('.')
    const nums = []
    let nonCanonical = false
    for (const seg of segs) {
      const r = ilParseSegment(seg)
      if (r === null || r.value === null) return { isIp: false }
      if (r.nonCanonical) nonCanonical = true
      nums.push(r.value)
    }
    let b
    if (nums.length === 1) {
      const v = nums[0]
      if (v < 0 || v > 0xFFFFFFFF) return { isIp: false }
      b = [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]
      nonCanonical = true
    } else if (nums.length === 2) {
      if (nums[0] > 255 || nums[1] > 0xFFFFFF) return { isIp: false }
      b = [nums[0], (nums[1] >>> 16) & 255, (nums[1] >>> 8) & 255, nums[1] & 255]
      nonCanonical = true
    } else if (nums.length === 3) {
      if (nums[0] > 255 || nums[1] > 255 || nums[2] > 0xFFFF) return { isIp: false }
      b = [nums[0], nums[1], (nums[2] >>> 8) & 255, nums[2] & 255]
      nonCanonical = true
    } else if (nums.length === 4) {
      for (const v of nums) if (v > 255) return { isIp: false }
      b = nums
    } else {
      return { isIp: false }
    }

    const canonical = b.join('.')
    const result = { isIp: true, canonical: canonical, class: ilClassifyV4(canonical), reasons: [] }
    if (nonCanonical || h !== canonical) result.reasons.push(IL_REASON.AMBIGUOUS_ENCODING)
    return result
  }

  classifyV6 (h) {
    const lower = h.toLowerCase()
    const mapped = '::ffff:'
    if (lower.startsWith(mapped)) {
      const r = this.normalize(h.slice(mapped.length))
      if (r.isIp) {
        r.reasons.push(IL_REASON.IPV6_MAPPED_INTERNAL)
        return r
      }
    }
    if (lower.startsWith('::') && h.slice(2).indexOf('.') >= 0) {
      const r = this.normalize(h.slice(2))
      if (r.isIp) return r
    }
    if (lower === '::1') {
      return { isIp: true, class: 'loopback', reasons: [IL_REASON.IPV6_LOOPBACK] }
    }
    const groups = lower.split(':')
    if (groups.length === 8 && groups.slice(0, 7).every((g) => g === '' || g === '0') && groups[7] === '1') {
      return { isIp: true, class: 'loopback', reasons: [IL_REASON.IPV6_LOOPBACK] }
    }
    return { isIp: true, class: 'public', reasons: [] }
  }

  isInternal (host) {
    const r = this.normalize(host)
    return r.isIp && (r.class === 'loopback' || r.class === 'private' || r.class === 'linklocal')
  }
}

module.exports = Object.freeze({
  IL_REASON: IL_REASON,
  ilClassifyV4: ilClassifyV4,
  IpLiteralGuard: IpLiteralGuard
})
