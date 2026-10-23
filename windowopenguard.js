'use strict'

// windowopenguard.js —— window.open 调用特性守卫。
//
// 威胁模型：
//   window.open(url, '_blank') 不指定 noopener 时，新窗口持有 window.opener，可反向改写
//   原窗口地址（tab-nabbing）。第三个参数 features 里必须显式 noopener（现代浏览器也支持
//   noreferrer 隐含 noopener）。历史代码常见 "noopener=yes" 拼写/值写法差异，需识别。
// 规则：
//   - 打开跨源 URL：features 必须含 noopener（或 noreferrer）；
//   - target=_blank 且无 features：命中；
//   - features 里 "noopener=0/no" 视为显式关闭，同样危险；
//   - 同源可按策略豁免。

const WOG_REASON = Object.freeze({
  NEW_WINDOW_NO_OPENER: 'wog-new-window-without-noopener',
  NOOPENER_EXPLICITLY_DISABLED: 'wog-noopener-explicitly-disabled',
  UNKNOWN_FEATURE: 'wog-unknown-feature'
})

const WOG_KNOWN_FEATURES = Object.freeze({
  popup: true, width: true, height: true, left: true, top: true,
  noopener: true, noreferrer: true, menubar: true, toolbar: true,
  location: true, status: true, resizable: true, scrollbars: true,
  centerscreen: true, _crx: true
})

function defaultWogPolicy () {
  return { sameOriginExempt: true, rejectUnknownFeatures: false }
}

function wogOriginOf (url) {
  const s = String(url || '')
  const i = s.indexOf('://')
  if (i < 0) return ''
  const rest = s.slice(i + 3)
  const slash = rest.indexOf('/')
  return s.slice(0, i + 3) + (slash < 0 ? rest : rest.slice(0, slash)).toLowerCase()
}

// 解析 features 串为小写键→原始小写值（无值键为 'true'）。
function wogParseFeatures (features) {
  const out = {}
  if (!features) return out
  const s = String(features)
  const parts = s.split(',')
  parts.forEach((p) => {
    const seg = p.trim()
    if (seg === '') return
    const eq = seg.indexOf('=')
    if (eq < 0) out[seg.toLowerCase()] = 'true'
    else out[seg.slice(0, eq).trim().toLowerCase()] = seg.slice(eq + 1).trim().toLowerCase()
  })
  return out
}

class WindowOpenGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultWogPolicy(), policy || {})
  }

  // call: { url, target, features, baseOrigin }
  evaluate (call) {
    const c = call || {}
    const pol = this.policy
    const findings = []
    const target = (c.target || '_blank').toLowerCase()
    const opensNew = target === '_blank' || target === ''
    if (!opensNew) return { safe: true, opensNew: false, findings }

    const from = String(c.baseOrigin || '').toLowerCase()
    const to = wogOriginOf(c.url)
    const cross = to !== '' && from !== '' && to !== from
    if (pol.sameOriginExempt && to !== '' && !cross) {
      return { safe: true, opensNew: true, crossOrigin: false, findings }
    }

    const feats = wogParseFeatures(c.features)
    if (pol.rejectUnknownFeatures) {
      Object.keys(feats).forEach((k) => {
        if (!WOG_KNOWN_FEATURES[k]) findings.push({ reason: WOG_REASON.UNKNOWN_FEATURE, feature: k })
      })
    }
    const noopenerVal = feats.noopener
    const hasNoreferrer = feats.noreferrer === 'true' || feats.noreferrer === 'yes' || feats.noreferrer === '1'
    if (noopenerVal === '0' || noopenerVal === 'no' || noopenerVal === 'false') {
      findings.push({ reason: WOG_REASON.NOOPENER_EXPLICITLY_DISABLED })
    } else {
      const hasNoopener = noopenerVal === undefined ? false :
        (noopenerVal === 'true' || noopenerVal === 'yes' || noopenerVal === '1' || noopenerVal === '')
      if (!hasNoopener && !hasNoreferrer) {
        findings.push({ reason: WOG_REASON.NEW_WINDOW_NO_OPENER })
      }
    }
    return { safe: findings.length === 0, opensNew: true, crossOrigin: cross, features: feats, findings }
  }
}

module.exports = Object.freeze({
  WOG_REASON: WOG_REASON,
  WOG_KNOWN_FEATURES: WOG_KNOWN_FEATURES,
  defaultWogPolicy: defaultWogPolicy,
  wogParseFeatures: wogParseFeatures,
  WindowOpenGuard: WindowOpenGuard
})
