'use strict'

// serviceworkerguard.js —— Service Worker 注册来源、作用域与更新安全守卫。
//
// 威胁模型：
//   Service Worker 一旦注册就能长期拦截页面全部网络请求（含可改响应），是高权限后台脚本。风险：
//     - 在 http 来源注册（可被中间人植入持久 SW）；
//     - 注册脚本路径与作用域跨目录提权（script 在 /a/ 却想控制 /）；
//     - 作用域过宽（'/' 配合不可信子路径）；
//     - importScripts 拉取跨源/明文脚本；
//     - 多个同源 SW 作用域重叠造成不确定的拦截者。
//   本模块审计注册参数与作用域包含关系。纯字符路径判定，不使用正则。

const SW_REASON = Object.freeze({
  INSECURE_ORIGIN: 'service-worker-registered-on-non-secure-origin',
  SCOPE_NOT_UNDER_SCRIPT: 'service-worker-scope-escapes-script-directory',
  SCOPE_TOO_BROAD: 'service-worker-scope-is-site-root-from-untrusted-path',
  IMPORT_INSECURE: 'service-worker-importscripts-over-http-or-cross-origin',
  SCOPE_OVERLAP: 'service-worker-scopes-overlap'
})

function swDirOf (path) {
  const p = String(path)
  const slash = p.lastIndexOf('/')
  return slash < 0 ? '/' : p.slice(0, slash + 1)
}

function swIsUnder (childDir, parentDir) {
  return childDir === parentDir ||
    (parentDir === '/') ||
    (childDir.indexOf(parentDir) === 0)
}

class ServiceWorkerGuard {
  // in: { secureOrigin, scriptUrl(path), scope(path), imports:[url], existingScopes:[path] }
  evaluate (input) {
    const inp = input || {}
    const findings = []
    if (inp.secureOrigin !== true) findings.push({ reason: SW_REASON.INSECURE_ORIGIN })

    const scriptPath = String(inp.scriptPath || '/sw.js')
    const scopePath = String(inp.scope || '/')
    const scriptDir = swDirOf(scriptPath)

    if (!swIsUnder(scopePath, scriptDir) && scopePath !== scriptDir) {
      // 作用域若不在脚本所在目录之下即提权（忽略 Service-Worker-Allowed 头时的保守判定）
      if (scopePath.indexOf(scriptDir) !== 0) {
        findings.push({ reason: SW_REASON.SCOPE_NOT_UNDER_SCRIPT })
      }
    }
    if (scopePath === '/' && scriptDir !== '/') {
      findings.push({ reason: SW_REASON.SCOPE_TOO_BROAD })
    }

    for (const u of inp.imports || []) {
      const url = String(u)
      if (url.indexOf('http://') === 0) findings.push({ reason: SW_REASON.IMPORT_INSECURE, detail: url })
    }

    for (const existing of inp.existingScopes || []) {
      const e = String(existing)
      if (swIsUnder(scopePath, e) || swIsUnder(e, scopePath)) {
        if (e !== scopePath) findings.push({ reason: SW_REASON.SCOPE_OVERLAP, detail: e })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  SW_REASON: SW_REASON,
  swDirOf: swDirOf,
  swIsUnder: swIsUnder,
  ServiceWorkerGuard: ServiceWorkerGuard
})
