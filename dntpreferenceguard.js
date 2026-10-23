'use strict'

// dntpreferenceguard.js —— Do Not Track / Global Privacy Control 偏好透传守卫。
//
// 威胁模型（隐私一致性）：
//   用户在设置里开了"向网站发送请勿跟踪"，浏览器却因为导航方式/内置请求/跟踪域白名单而漏发或被
//   覆盖，会让隐私设置名存实亡。需要审计：
//     - 用户开启 DNT 后，所有顶层与子资源请求是否都带 DNT:1（或 Sec-GPC:1）；
//     - 是否对特定域关掉（跟踪域豁免）；
//     - 配置变更是否生效；http 与 https 是否一致。
//   本模块纯做策略核对：给定用户偏好与一条出站请求，判定头是否应存在/被正确透传。纯字符匹配。

const DNT_REASON = Object.freeze({
  DNT_MISSING: 'do-not-track-enabled-but-header-not-sent',
  GPC_MISSING: 'global-privacy-control-enabled-but-header-not-sent',
  DNT_FORCED_OFF: 'do-not-track-explicitly-disabled-for-a-domain',
  WRONG_VALUE: 'do-not-track-header-value-is-not-1'
})

function dntLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

class DntPreferenceGuard {
  // settings: { dntEnabled, gpcEnabled, exemptDomains:[] }
  constructor (settings) {
    const s = settings || {}
    this.dnt = s.dntEnabled === true
    this.gpc = s.gpcEnabled === true
    this.exempt = new Set((s.exemptDomains || []).map(dntLower))
  }

  // request: { host, headers: { dnt, 'sec-gpc' }, isUserInitiatedTopNav }
  evaluate (request) {
    const req = request || {}
    const host = dntLower(String(req.host || ''))
    const headers = req.headers || {}
    const findings = []
    const exempt = this.exempt.has(host)

    if (exempt && (this.dnt || this.gpc)) {
      findings.push({ reason: DNT_REASON.DNT_FORCED_OFF, detail: host })
    }
    if (this.dnt && !exempt) {
      const v = headers.dnt === undefined ? headers.DNT : headers.dnt
      if (v === undefined) findings.push({ reason: DNT_REASON.DNT_MISSING })
      else if (String(v) !== '1') findings.push({ reason: DNT_REASON.WRONG_VALUE, detail: String(v) })
    }
    if (this.gpc && !exempt) {
      const g = headers['sec-gpc'] === undefined ? headers['Sec-GPC'] : headers['sec-gpc']
      if (g === undefined || String(g) !== '1') findings.push({ reason: DNT_REASON.GPC_MISSING })
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  DNT_REASON: DNT_REASON,
  DntPreferenceGuard: DntPreferenceGuard
})
