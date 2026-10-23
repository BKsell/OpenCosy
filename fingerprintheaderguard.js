'use strict'

// fingerprintheaderguard.js —— 技术栈指纹泄露响应头守卫。
//
// 威胁模型：
//   Server、X-Powered-By、X-AspNet-Version、X-Runtime、X-Version 等头会暴露服务器软件、
//   语言框架及精确版本，攻击者据此匹配已知 CVE、定制利用。应移除或置空这些头。
//   风险分级：
//     - X-Powered-By / X-AspNet-Version / X-AspNetMvc-Version：纯泄露，应删除；
//     - Server：常含 "nginx/1.20.1" 版本，建议去版本；
//     - X-Runtime：泄露计时，可辅助时序侧信道；
//     - Via / X-Served-By：暴露内部主机名/代理拓扑；
//   另：值里出现明确版本号（数字.数字）单独给 finding，即使头名不在黑名单。

const FPH_REASON = Object.freeze({
  DISCLOSING_HEADER: 'fph-disclosing-header',
  VERSION_IN_VALUE: 'fph-version-in-value',
  INTERNAL_HOSTNAME: 'fph-internal-hostname'
})

// 默认建议清除的头（小写）。
const FPH_REMOVE = Object.freeze({
  'x-powered-by': true,
  'x-aspnet-version': true,
  'x-aspnetmvc-version': true,
  'x-generator': true,
  'x-runtime': true,
  'x-version': true
})
// 建议脱敏（去版本/去主机名）的头。
const FPH_SCRUB = Object.freeze({
  server: true,
  via: true,
  'x-served-by': true,
  'x-cache-servers': true
})

function defaultFphPolicy () {
  return { detectVersionDigits: true, detectInternalHost: true }
}

// 纯字符判断是否含 "数字.数字" 形态的版本号。
function fphContainsVersion (s) {
  for (let i = 0; i + 2 < s.length; i++) {
    const c0 = s.charCodeAt(i)
    const c1 = s.charCodeAt(i + 1)
    const c2 = s.charCodeAt(i + 2)
    if (c0 >= 48 && c0 <= 57 && s.charAt(i + 1) === '.' && c2 >= 48 && c2 <= 57) {
      return true
    }
  }
  return false
}

// 内部主机名线索：localhost / .internal / .local / 10. / 192.168. 等。
function fphContainsInternal (s) {
  const v = s.toLowerCase()
  const marks = ['localhost', '.internal', '.local', '.lan', '127.0.0.1', '10.', '192.168.', '172.16.']
  for (let i = 0; i < marks.length; i++) {
    if (v.indexOf(marks[i]) >= 0) return true
  }
  return false
}

class FingerprintHeaderGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultFphPolicy(), policy || {})
    this.removeSet = Object.assign({}, FPH_REMOVE, policy && policy.extraRemove ? policy.extraRemove : {})
    this.scrubSet = Object.assign({}, FPH_SCRUB, policy && policy.extraScrub ? policy.extraScrub : {})
  }

  // headers: { 头名(大小写随意): 值 }，可给数组值（多头）。
  evaluate (headers) {
    const pol = this.policy
    const findings = []
    const h = headers || {}
    Object.keys(h).forEach((name) => {
      const lower = name.toLowerCase()
      const rawVals = Array.isArray(h[name]) ? h[name] : [h[name]]
      rawVals.forEach((val) => {
        const v = val === null || val === undefined ? '' : String(val)
        if (this.removeSet[lower]) {
          findings.push({ reason: FPH_REASON.DISCLOSING_HEADER, header: lower, value: v })
          return
        }
        if (this.scrubSet[lower]) {
          if (pol.detectVersionDigits && fphContainsVersion(v)) {
            findings.push({ reason: FPH_REASON.VERSION_IN_VALUE, header: lower, value: v })
          }
          if (pol.detectInternalHost && fphContainsInternal(v)) {
            findings.push({ reason: FPH_REASON.INTERNAL_HOSTNAME, header: lower, value: v })
          }
        }
      })
    })
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  FPH_REASON: FPH_REASON,
  FPH_REMOVE: FPH_REMOVE,
  FPH_SCRUB: FPH_SCRUB,
  defaultFphPolicy: defaultFphPolicy,
  fphContainsVersion: fphContainsVersion,
  FingerprintHeaderGuard: FingerprintHeaderGuard
})
