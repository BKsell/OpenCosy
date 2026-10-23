'use strict'

// contentlengthguard.js —— 请求/响应 Content-Length 与实际字节一致性守卫（请求走私/截断辅助）。
//
// 威胁模型：
//   下载器若信任声明的 Content-Length：
//     - 声明极大但连接提前关闭 → 预分配巨量内存/磁盘（资源耗尽）；
//     - 声明很小却持续发送多余字节 → 多余字节可能被当成下一条响应（与 keep-alive 代理组合可走私）；
//     - Content-Length 与分块 Transfer-Encoding 同时存在（交 requestsmugglingguard，本模块聚焦长度）；
//     - 非数字、负数、超大（超 JS 安全整数/配置上限）。
//   本模块在"读 body 过程中"记账：开始时记录声明长度，结束时核对实际字节。纯数值判定，不使用正则。

const CL2_REASON = Object.freeze({
  BAD_FORMAT: 'content-length-not-a-non-negative-integer',
  OVER_LIMIT: 'content-length-exceeds-configured-max',
  SHORT_BODY: 'body-shorter-than-declared-content-length',
  EXTRA_BYTES: 'body-longer-than-declared-content-length',
  DECLARED_TOO_LARGE_FOR_PRECISION: 'content-length-exceeds-safe-integer-precision'
})

function clParse (raw) {
  const s = String(raw)
  if (s.length === 0) return { ok: false }
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 48 || c > 57) return { ok: false }
  }
  const n = Number(s)
  if (!Number.isSafeInteger(n)) return { ok: false, tooLarge: true }
  return { ok: true, value: n }
}

class ContentLengthGuard {
  // maxBytes：允许的最大声明长度。
  constructor (maxBytes) {
    this.maxBytes = typeof maxBytes === 'number' ? maxBytes : 5 * 1024 * 1024 * 1024
    this.received = 0
    this.declared = null
  }

  // 读到头时调用。
  begin (rawContentLength) {
    if (rawContentLength === null || rawContentLength === undefined || rawContentLength === '') {
      return { safe: true, findings: [], declared: null }
    }
    const p = clParse(rawContentLength)
    if (!p.ok) {
      const reason = p.tooLarge ? CL2_REASON.DECLARED_TOO_LARGE_FOR_PRECISION : CL2_REASON.BAD_FORMAT
      return { safe: false, findings: [{ reason: reason }] }
    }
    this.declared = p.value
    if (p.value > this.maxBytes) {
      return { safe: false, findings: [{ reason: CL2_REASON.OVER_LIMIT, detail: String(p.value) }] }
    }
    return { safe: true, findings: [], declared: p.value }
  }

  account (n) {
    this.received += n
    if (this.declared !== null && this.received > this.declared) {
      return { safe: false, findings: [{ reason: CL2_REASON.EXTRA_BYTES }] }
    }
    return { safe: true, findings: [] }
  }

  // 连接正常结束时核对。
  finish (truncated) {
    if (truncated === true && this.declared !== null && this.received < this.declared) {
      return { safe: false, findings: [{ reason: CL2_REASON.SHORT_BODY }] }
    }
    if (this.declared !== null && this.received !== this.declared) {
      const reason = this.received < this.declared ? CL2_REASON.SHORT_BODY : CL2_REASON.EXTRA_BYTES
      return { safe: false, findings: [{ reason: reason }] }
    }
    return { safe: true, findings: [] }
  }
}

module.exports = Object.freeze({
  CL2_REASON: CL2_REASON,
  clParse: clParse,
  ContentLengthGuard: ContentLengthGuard
})
