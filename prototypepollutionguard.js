'use strict'

// prototypepollutionguard.js —— 外部 JSON/配置合并时的原型链污染守卫。
//
// 威胁模型：
//   浏览器要合并远端设置、扩展选项、恢复的会话 JSON。若递归合并信任键名 "__proto__"、
//   "constructor"、"prototype"，攻击者可污染 Object.prototype：
//     { "__proto__": { "isAdmin": true } } 之后任意对象 {}.isAdmin === true，
//     进而绕过授权、让后续 hasOwnProperty/属性检查失效、触发依赖原型的代码路径。
//   本模块：识别危险键、审计待合并对象，并提供 safeMerge（不触碰原型链的深度合并）。

const PP_DANGEROUS = Object.freeze(['__proto__', 'constructor', 'prototype'])

const PP_REASON = Object.freeze({
  PROTO_KEY: 'object-merge-targets-proto-or-constructor',
  NON_OBJECT_SINK: 'merge-target-must-be-plain-object',
  TOO_DEEP: 'object-nesting-exceeds-depth-limit'
})

function ppIsPlain (v) {
  if (v === null || typeof v !== 'object') return false
  const proto = Object.getPrototypeOf(v)
  return proto === Object.prototype || proto === null
}

function ppIsDangerousKey (k) {
  return PP_DANGEROUS.indexOf(k) >= 0
}

function ppAudit (value, depth) {
  const findings = []
  const maxDepth = typeof depth === 'number' ? depth : 32
  const walk = (node, level, path) => {
    if (level > maxDepth) {
      findings.push({ reason: PP_REASON.TOO_DEEP, detail: path })
      return
    }
    if (!ppIsPlain(node)) return
    for (const key of Object.keys(node)) {
      if (ppIsDangerousKey(key)) {
        findings.push({ reason: PP_REASON.PROTO_KEY, detail: path + '.' + key })
      }
      walk(node[key], level + 1, path + '.' + key)
    }
  }
  walk(value, 0, '$')
  return { safe: findings.length === 0, findings: findings }
}

// safeMerge：以 target 为底，深度合并 source。危险键跳过；遇到污染键的节点直接忽略该分支。
function safeMerge (target, source, depth) {
  if (!ppIsPlain(target)) {
    return { safe: false, result: target, findings: [{ reason: PP_REASON.NON_OBJECT_SINK }] }
  }
  const audit = ppAudit(source, depth)
  const maxDepth = typeof depth === 'number' ? depth : 32
  const merge = (dst, src, level) => {
    for (const key of Object.keys(src)) {
      if (ppIsDangerousKey(key)) continue
      const sv = src[key]
      if (ppIsPlain(sv)) {
        if (level >= maxDepth) continue
        if (!ppIsPlain(dst[key])) dst[key] = {}
        merge(dst[key], sv, level + 1)
      } else {
        dst[key] = sv
      }
    }
  }
  merge(target, source, 0)
  return { safe: audit.safe, result: target, findings: audit.findings }
}

class PrototypePollutionGuard {
  audit (value, depth) {
    return ppAudit(value, depth)
  }

  merge (target, source, depth) {
    return safeMerge(target, source, depth)
  }
}

module.exports = Object.freeze({
  PP_REASON: PP_REASON,
  PP_DANGEROUS: PP_DANGEROUS,
  ppIsPlain: ppIsPlain,
  safeMerge: safeMerge,
  PrototypePollutionGuard: PrototypePollutionGuard
})
