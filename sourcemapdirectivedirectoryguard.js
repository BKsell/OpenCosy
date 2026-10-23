'use strict'

// sourcemapdirectivedirectoryguard.js —— Source Map 暴露指令目录。
//
// 威胁模型：
//   sourceMappingURL/eval-source-map/inline-source-map 在生产暴露源码与路径，开发构建指令常规。纯字符查表，不用正则。

const SMD_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const SMD_BLOCK = Object.freeze([
  '//# sourceMappingURL=',
  '//# sourceMappingURL=http',
  '//# sourceMappingURL=https',
  '//# sourceMappingURL=//',
  '//# sourceURL=',
  '/*# sourceMappingURL=',
  '//@ sourceMappingURL=',
  '//@ sourceURL=',
  '# sourceMappingURL=http',
  '# sourceMappingURL=file',
  'eval-source-map',
  'inline-source-map',
  'cheap-module-eval-source-map',
  'eval-cheap-module-source-map',
])

const SMD_WARN = Object.freeze([
  'source-map',
  'sourcemap',
  'sourceMappingURL',
  'sourcesContent',
  'hidden-source-map',
  'nosources-source-map',
  'cheap-source-map',
  'cheap-module-source-map',
  'inline-cheap-source-map',
  'source-map-loader',
  'SourceMapDevToolPlugin',
  'devtool',
  'production-map',
  'upload-sourcemap',
])

const SMD_ALLOW = Object.freeze([
  'none',
  'false',
  'internal',
  'dev',
  'development',
  'test',
  'build',
  'debug-only',
])

function SMDLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function SMDIn (list, v) {
  for (const x of list) { if (SMDLower(x) === v) return true }
  return false
}

function SMDClassify (tok) {
  const v = SMDLower(String(tok == null ? '' : tok).trim())
  if (SMDIn(SMD_BLOCK, v)) return SMD_CLASS.BLOCK
  if (SMDIn(SMD_WARN, v)) return SMD_CLASS.WARN
  if (SMDIn(SMD_ALLOW, v)) return SMD_CLASS.ALLOW
  return SMD_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  SMD_CLASS: SMD_CLASS,
  SMD_BLOCK: SMD_BLOCK,
  SMD_WARN: SMD_WARN,
  SMD_ALLOW: SMD_ALLOW,
  SMDClassify: SMDClassify
})
