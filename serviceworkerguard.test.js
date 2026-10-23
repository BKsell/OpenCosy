'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { ServiceWorkerGuard, SW_REASON, swDirOf, swIsUnder } = require('./serviceworkerguard.js')

function reasons (i) {
  return new ServiceWorkerGuard().evaluate(i).findings.map((f) => f.reason)
}

test('directory helper', () => {
  assert.equal(swDirOf('/a/sw.js'), '/a/')
  assert.equal(swIsUnder('/a/b/', '/a/'), true)
  assert.equal(swIsUnder('/a/', '/a/b/'), false)
})

test('root sw on secure origin safe', () => {
  const r = new ServiceWorkerGuard().evaluate({
    secureOrigin: true, scriptPath: '/sw.js', scope: '/'
  })
  assert.equal(r.safe, true)
})

test('non-secure origin rejected', () => {
  assert.ok(reasons({ secureOrigin: false, scriptPath: '/sw.js', scope: '/' }).includes(SW_REASON.INSECURE_ORIGIN))
})

test('scope escaping script dir flagged', () => {
  const r = reasons({ secureOrigin: true, scriptPath: '/a/sw.js', scope: '/' })
  assert.ok(r.includes(SW_REASON.SCOPE_NOT_UNDER_SCRIPT))
  assert.ok(r.includes(SW_REASON.SCOPE_TOO_BROAD))
})

test('scope under script dir safe', () => {
  const r = new ServiceWorkerGuard().evaluate({ secureOrigin: true, scriptPath: '/a/sw.js', scope: '/a/' })
  assert.equal(r.safe, true)
})

test('http import flagged', () => {
  const r = reasons({ secureOrigin: true, scriptPath: '/sw.js', scope: '/', imports: ['http://cdn/lib.js'] })
  assert.ok(r.includes(SW_REASON.IMPORT_INSECURE))
})

test('overlapping existing scope flagged', () => {
  const r = reasons({
    secureOrigin: true, scriptPath: '/a/sw.js', scope: '/a/', existingScopes: ['/']
  })
  assert.ok(r.includes(SW_REASON.SCOPE_OVERLAP))
})

test('identical existing scope not flagged as overlap', () => {
  const r = new ServiceWorkerGuard().evaluate({
    secureOrigin: true, scriptPath: '/a/sw.js', scope: '/a/', existingScopes: ['/a/']
  })
  assert.equal(r.safe, true)
})
