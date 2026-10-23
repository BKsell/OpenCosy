'use strict'

// globaleventhandlerdirectoryguard.js —— 全局 on* 事件处理器属性目录。
//
// 威胁模型：
//   元素上的内联 on* 属性在 CSP unsafe-inline 下直接执行脚本，应改 addEventListener。本目录按 on* 名分级，
//   纯字符查表，不用正则。

const GEH_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const GEH_BLOCK = Object.freeze([
  'onabort',
  'onafterprint',
  'onafterscriptexecute',
  'onanimationcancel',
  'onanimationend',
  'onanimationiteration',
  'onanimationstart',
  'onauxclick',
  'onbeforeinput',
  'onbeforematch',
  'onbeforeprint',
  'onbeforescriptexecute',
  'onbeforetoggle',
  'onbeforeunload',
  'onblur',
  'oncancel',
  'oncanplay',
  'oncanplaythrough',
  'onchange',
  'onclick',
  'onclose',
  'oncontextlost',
  'oncontextmenu',
  'oncontextrestored',
  'oncopy',
  'oncuechange',
  'oncut',
  'ondblclick',
  'ondrag',
  'ondragend',
  'ondragenter',
  'ondragleave',
  'ondragover',
  'ondragstart',
  'ondrop',
  'ondurationchange',
  'onemptied',
  'onended',
  'onerror',
  'onfocus',
  'onfocusin',
  'onfocusout',
  'onformdata',
  'ongotpointercapture',
  'oninput',
  'oninvalid',
  'onkeydown',
  'onkeypress',
  'onkeyup',
  'onload',
  'onloadeddata',
  'onloadedmetadata',
  'onloadstart',
  'onlostpointercapture',
  'onmessage',
  'onmessageerror',
  'onmousedown',
  'onmouseenter',
  'onmouseleave',
  'onmousemove',
  'onmouseout',
  'onmouseover',
  'onmouseup',
  'onmousewheel',
  'onoffline',
  'ononline',
  'onpagehide',
  'onpageshow',
  'onpaste',
  'onpause',
  'onplay',
  'onplaying',
  'onpointercancel',
  'onpointerdown',
  'onpointerenter',
  'onpointerleave',
  'onpointermove',
  'onpointerout',
  'onpointerover',
  'onpointerrawupdate',
  'onpointerup',
  'onpopstate',
  'onprogress',
  'onratechange',
  'onreset',
  'onresize',
  'onscroll',
  'onscrollend',
  'onsecuritypolicyviolation',
  'onseeked',
  'onseeking',
  'onselect',
  'onselectionchange',
  'onselectstart',
  'onslotchange',
  'onstalled',
  'onstorage',
  'onsubmit',
  'onsuspend',
  'ontimeupdate',
  'ontoggle',
  'ontouchcancel',
  'ontouchend',
  'ontouchmove',
  'ontouchstart',
  'ontransitioncancel',
  'ontransitionend',
  'ontransitionrun',
  'ontransitionstart',
  'onunhandledrejection',
  'onunload',
  'onvolumechange',
  'onwaiting',
  'onwebkitanimationend',
  'onwebkitanimationiteration',
  'onwebkitanimationstart',
  'onwebkittransitionend',
  'onwheel',
  'onfullscreenchange',
  'onfullscreenerror',
  'onpointerlockchange',
  'onpointerlockerror',
  'onreadystatechange',
  'ondevicemotion',
  'ondeviceorientation',
  'ondeviceorientationabsolute',
  'onsearch',
  'onhashchange',
  'onlanguagechange',
  'onbeforeinstallprompt',
  'onappinstalled',
  'onbeforexrselect',
  'oncontentvisibilityautostatechange',
  'ontextupdate',
  'ontextformatupdate',
])

const GEH_WARN = Object.freeze([
])

const GEH_ALLOW = Object.freeze([
])

function GEHLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function GEHIn (list, v) {
  for (const x of list) { if (GEHLower(x) === v) return true }
  return false
}

function GEHClassify (tok) {
  const v = GEHLower(String(tok == null ? '' : tok).trim())
  if (GEHIn(GEH_BLOCK, v)) return GEH_CLASS.BLOCK
  if (GEHIn(GEH_WARN, v)) return GEH_CLASS.WARN
  if (GEHIn(GEH_ALLOW, v)) return GEH_CLASS.ALLOW
  return GEH_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  GEH_CLASS: GEH_CLASS,
  GEH_BLOCK: GEH_BLOCK,
  GEH_WARN: GEH_WARN,
  GEH_ALLOW: GEH_ALLOW,
  GEHClassify: GEHClassify
})
