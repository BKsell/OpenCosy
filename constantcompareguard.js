'use strict'

// constantcompareguard.js —— 密钥/令牌/签名比较的常量时间包装与长度守卫。
//
// 威胁模型：
//   比较 token、CSRF 值、签名摘要时用 a === b 会在第一个不同字节处提前返回，形成时序侧信道，
//   攻击者可逐字节猜出正确值。浏览器/Node 场景虽有网络抖动，但本地 IPC、环回、同源计时精度高。
//   本模块提供固定工作量的比较：先比长度（长度不同也要做等量运算），再逐字节异或累加不提前返回；
//   并审计调用点是否误用了普通比较（通过标记可疑比较结果）。纯运算，不使用正则。

const CC_REASON = Object.freeze({
  LENGTH_MISMATCH: 'constant-compare-input-length-differs',
  NON_STRING: 'constant-compare-input-not-string',
  EMPTY_SECRET: 'constant-compare-secret-is-empty'
})

function ccLen (s) {
  // 用 UTF-16 码元计数；调用方应保证两侧编码一致。
  return s.length
}

// timingSafeEqualString：无论是否相等都遍历到 maxLen，返回布尔。
function timingSafeEqualString (a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  const la = ccLen(a)
  const lb = ccLen(b)
  const max = la >= lb ? la : lb
  let diff = la ^ lb
  for (let i = 0; i < max; i++) {
    // 越界侧用 0，保证循环次数只由 max 决定
    const ca = i < la ? a.charCodeAt(i) : 0
    const cb = i < lb ? b.charCodeAt(i) : 0
    diff |= ca ^ cb
  }
  return diff === 0
}

class ConstantCompareGuard {
  auditInputs (a, b) {
    const findings = []
    if (typeof a !== 'string' || typeof b !== 'string') {
      findings.push({ reason: CC_REASON.NON_STRING })
    }
    if (typeof a === 'string' && a.length === 0) findings.push({ reason: CC_REASON.EMPTY_SECRET })
    if (typeof a === 'string' && typeof b === 'string' && a.length !== b.length) {
      findings.push({ reason: CC_REASON.LENGTH_MISMATCH })
    }
    return { safe: findings.length === 0, findings: findings }
  }

  // 比较结果只反映相等性；即使长度不同也完成等量工作。
  equals (a, b) {
    return timingSafeEqualString(a, b)
  }
}

module.exports = Object.freeze({
  CC_REASON: CC_REASON,
  timingSafeEqualString: timingSafeEqualString,
  ConstantCompareGuard: ConstantCompareGuard
})
