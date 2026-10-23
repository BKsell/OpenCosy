'use strict'

// htmlelementdirectoryguard.js —— HTML 元素风险分级目录。
//
// 威胁模型：
//   script/iframe/object/embed/link/meta/base/form 等元素可执行脚本或改变导航/资源加载，
//   纯结构化元素低风险。纯字符查表，不用正则。

const HTD_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const HTD_BLOCK = Object.freeze([
  'script',
  'iframe',
  'object',
  'embed',
  'applet',
  'link',
  'meta',
  'base',
  'frame',
  'frameset',
])

const HTD_WARN = Object.freeze([
  'a',
  'area',
  'form',
  'button',
  'input',
  'select',
  'option',
  'textarea',
  'details',
  'dialog',
  'noscript',
  'template',
  'portal',
  'fencedframe',
  'webview',
  'img',
  'picture',
  'source',
  'video',
  'audio',
  'track',
  'canvas',
  'map',
  'svg',
  'math',
  'foreignObject',
  'use',
  'image',
  'animate',
  'animateMotion',
  'animateTransform',
  'set',
  'handler',
  'mpath',
  'slot',
  'content',
  'nav',
  'aside',
  'blockquote',
  'q',
  'cite',
  'ins',
  'del',
  'output',
  'progress',
  'meter',
  'datalist',
  'optgroup',
])

const HTD_ALLOW = Object.freeze([
  'html',
  'head',
  'body',
  'title',
  'style',
  'div',
  'span',
  'p',
  'br',
  'hr',
  'pre',
  'code',
  'kbd',
  'samp',
  'var',
  'b',
  'strong',
  'i',
  'em',
  'mark',
  'small',
  'u',
  's',
  'sub',
  'sup',
  'ruby',
  'rt',
  'rp',
  'bdi',
  'bdo',
  'abbr',
  'time',
  'data',
  'dfn',
  'dl',
  'dt',
  'dd',
  'ol',
  'ul',
  'li',
  'figure',
  'figcaption',
  'table',
  'caption',
  'colgroup',
  'col',
  'tbody',
  'thead',
  'tfoot',
  'tr',
  'td',
  'th',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'fieldset',
  'legend',
  'label',
  'main',
  'section',
  'article',
  'header',
  'footer',
  'address',
  'summary',
  'wbr',
  'param',
])

function HTDLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function HTDIn (list, v) {
  for (const x of list) { if (HTDLower(x) === v) return true }
  return false
}

function HTDClassify (tok) {
  const v = HTDLower(String(tok == null ? '' : tok).trim())
  if (HTDIn(HTD_BLOCK, v)) return HTD_CLASS.BLOCK
  if (HTDIn(HTD_WARN, v)) return HTD_CLASS.WARN
  if (HTDIn(HTD_ALLOW, v)) return HTD_CLASS.ALLOW
  return HTD_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  HTD_CLASS: HTD_CLASS,
  HTD_BLOCK: HTD_BLOCK,
  HTD_WARN: HTD_WARN,
  HTD_ALLOW: HTD_ALLOW,
  HTDClassify: HTDClassify
})
