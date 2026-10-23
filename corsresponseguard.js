'use strict'

// corsresponseguard.js —— 跨域响应头（CORS）安全组合守卫。
//
// 威胁模型：
//   Access-Control-Allow-Origin（ACAO）配置错误会把带凭据的跨源数据暴露给任意外站：
//     - ACAO:* 同时 Access-Control-Allow-Credentials:true：浏览器实际会拒绝，但错误的网关/
//       旧实现可能仍放行；无论如何这是矛盾且危险的信号；
//     - ACAO 反射任意 Origin 且允许凭据：等价于 "*"，是最常见的 CORS 灾难配置；
//     - ACAO:* 配合 null 信任链：sandbox/data 页 Origin 为 null，被加入白名单即可读凭据；
//     - Allow-Credentials:true 必须配精确来源（不能 *、不能反射未校验来源）；
//     - 重复 ACAO 头、控制字符走私。
//
// 本模块评估"响应头 + 服务端是否做来源校验（allowlistMatched）"。

const CORS_REASON = Object.freeze({
  WILDCARD_WITH_CREDENTIALS: 'cors-wildcard-with-credentials',
  REFLECTED_ORIGIN_WITH_CREDENTIALS: 'cors-reflected-origin-with-credentials',
  NULL_ORIGIN_ALLOWED: 'cors-null-origin-allowed',
  CREDENTIALS_WITHOUT_ALLOWLIST: 'cors-credentials-without-allowlist-match',
  MULTIPLE_ACAO: 'cors-multiple-allow-origin',
  CONTROL_CHAR: 'cors-control-char',
  WILDCARD_ANYWAY: 'cors-wildcard-permissive'
})

function defaultCorsPolicy () {
  return {
    credentialsRequireExactOrigin: true,
    rejectNullOrigin: true,
    rejectControlChars: true
  }
}

function corsHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

class CorsResponseGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultCorsPolicy(), policy || {})
  }

  // resp: { allowOrigin:string|null, allowCredentials:boolean, allowOriginCount?:number,
  //          allowlistMatched:boolean, requestedOrigin:string }
  evaluate (resp) {
    const pol = this.policy
    const r = resp || {}
    const findings = []
    const acaoList = r.allowOriginList || (r.allowOrigin === null || r.allowOrigin === undefined
      ? [] : [r.allowOrigin])
    if ((r.allowOriginCount || acaoList.length) > 1 || acaoList.length > 1) {
      findings.push({ reason: CORS_REASON.MULTIPLE_ACAO })
    }
    const acao = acaoList[0]
    if (acao === null || acao === undefined || String(acao).trim() === '') {
      return { safe: true, allowCredentials: !!r.allowCredentials, findings, cors: false }
    }
    const value = String(acao)
    if (pol.rejectControlChars && corsHasControlChar(value)) {
      findings.push({ reason: CORS_REASON.CONTROL_CHAR })
    }
    const cred = r.allowCredentials === true
    const trimmed = value.trim()
    const isWild = trimmed === '*'
    const reflectsNull = trimmed === 'null'
    const reflectsOrigin = r.requestedOrigin && trimmed === String(r.requestedOrigin)

    if (isWild) {
      findings.push({ reason: CORS_REASON.WILDCARD_ANYWAY })
      if (cred) findings.push({ reason: CORS_REASON.WILDCARD_WITH_CREDENTIALS })
    }
    if (reflectsNull && pol.rejectNullOrigin) {
      findings.push({ reason: CORS_REASON.NULL_ORIGIN_ALLOWED })
    }
    if (cred && pol.credentialsRequireExactOrigin) {
      // 带凭据时，只有"精确命中服务端白名单"的具体来源才安全。
      if (isWild) {
        // 已在上面记录 WILDCARD_WITH_CREDENTIALS。
      } else if (reflectsNull) {
        // null + credentials 已由 NULL_ORIGIN_ALLOWED 覆盖危险面。
      } else if (!r.allowlistMatched) {
        // 反射了请求 Origin（或给了未在白名单确认的来源）。
        if (reflectsOrigin) {
          findings.push({ reason: CORS_REASON.REFLECTED_ORIGIN_WITH_CREDENTIALS })
        } else {
          findings.push({ reason: CORS_REASON.CREDENTIALS_WITHOUT_ALLOWLIST })
        }
      }
    }
    return {
      safe: findings.length === 0,
      cors: true,
      allowOrigin: trimmed,
      allowCredentials: cred,
      findings: findings
    }
  }
}

module.exports = Object.freeze({
  CORS_REASON: CORS_REASON,
  defaultCorsPolicy: defaultCorsPolicy,
  CorsResponseGuard: CorsResponseGuard
})
