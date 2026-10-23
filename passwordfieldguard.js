'use strict'

// passwordfieldguard.js —— 密码输入框安全属性守卫（防泄露/自动填充滥用）。
//
// 威胁模型：
//   登录/改密表单的 <input type=password> 若缺正确属性，密码可能被缓存、被注入脚本读取、
//   被错误自动填充到第三方页面：
//     - 缺 autocomplete（登录应用 username/current-password，注册/new-password，改密 new-password），
//       浏览器可能误填，也无法正确区分登录与改密；
//     - 通过非 https 页面提交密码框（混合提交）；
//     - 密码框被禁用/只读之外却可被 spellcheck（拼写检查会把密码传给输入法/云拼写）；
//     - 密码框出现在非表单容器且没有显式 autocomplete=off 的一次性令牌场景（保守提示）；
//     - maxlength 缺失导致超长密码被截断（可用性/安全）。
//   纯属性判定，不使用正则。

const PF_REASON = Object.freeze({
  MISSING_AUTOCOMPLETE: 'password-field-missing-autocomplete-token',
  BAD_AUTOCOMPLETE: 'password-field-autocomplete-token-invalid',
  PASSWORD_ON_INSECURE_PAGE: 'password-field-present-on-non-https-page',
  SPELLCHECK_ON: 'password-field-has-spellcheck-enabled',
  WEAK_MAXLENGTH: 'password-field-allows-unbounded-or-tiny-length'
})

const VALID_AUTOCOMPLETE = [
  'off', 'on',
  'username', 'current-password', 'new-password',
  'one-time-code'
]

class PasswordFieldGuard {
  // field: { autocomplete, pageScheme, spellcheck, maxLength, formActionScheme }
  evaluate (field) {
    const f = field || {}
    const findings = []
    const ac = String(f.autocomplete === undefined || f.autocomplete === null ? '' : f.autocomplete).trim().toLowerCase()
    if (ac === '') {
      findings.push({ reason: PF_REASON.MISSING_AUTOCOMPLETE })
    } else if (VALID_AUTOCOMPLETE.indexOf(ac) < 0) {
      findings.push({ reason: PF_REASON.BAD_AUTOCOMPLETE, detail: ac })
    }
    const scheme = String(f.pageScheme || '').toLowerCase()
    if (scheme && scheme !== 'https') findings.push({ reason: PF_REASON.PASSWORD_ON_INSECURE_PAGE })
    const formScheme = String(f.formActionScheme || '').toLowerCase()
    if (formScheme && formScheme !== 'https' && formScheme !== '') {
      findings.push({ reason: PF_REASON.PASSWORD_ON_INSECURE_PAGE })
    }
    if (f.spellcheck === true || f.spellcheck === 'true' || f.spellcheck === '') {
      findings.push({ reason: PF_REASON.SPELLCHECK_ON })
    }
    // maxLength：未设（无界）允许，但 <8 会截断正常密码。
    if (f.maxLength !== undefined && f.maxLength !== null) {
      const n = Number(f.maxLength)
      if (Number.isInteger(n) && n > 0 && n < 8) findings.push({ reason: PF_REASON.WEAK_MAXLENGTH, detail: String(n) })
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  PF_REASON: PF_REASON,
  VALID_AUTOCOMPLETE: VALID_AUTOCOMPLETE,
  PasswordFieldGuard: PasswordFieldGuard
})
