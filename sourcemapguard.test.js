'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SourceMapGuard, SM2_REASON } = require('./sourcemapguard.js')

function reasons (asset) {
  return new SourceMapGuard().evaluate(asset).findings.map((f) => f.reason)
}

test('no directive is safe in production', () => {
  assert.equal(new SourceMapGuard().evaluate({ kind: 'js', text: 'var a=1;', production: true }).safe, true)
})

test('external map flagged in production', () => {
  const r = reasons({ kind: 'js', text: 'var a=1;\n//# sourceMappingURL=app.js.map', production: true })
  assert.ok(r.includes(SM2_REASON.SOURCEMAPPING_URL))
})

test('inline map flagged in production', () => {
  const r = reasons({ kind: 'js', text: 'var a=1;\n//# sourceMappingURL=data:application/json;base64,eyJ', production: true })
  assert.ok(r.includes(SM2_REASON.INLINE_SOURCE_MAP))
})

test('map allowed in development', () => {
  const r = new SourceMapGuard().evaluate({
    kind: 'js', text: 'var a=1;\n//# sourceMappingURL=app.js.map', production: false
  })
  assert.equal(r.safe, true)
})

test('css directive recognized', () => {
  const r = reasons({ kind: 'css', text: 'a{}\n/*# sourceMappingURL=styles.css.map */', production: true })
  assert.ok(r.includes(SM2_REASON.SOURCEMAPPING_URL))
})

test('map file served in production flagged', () => {
  assert.equal(new SourceMapGuard().assessMapServed(true).safe, false)
})

test('map file served in dev safe', () => {
  assert.equal(new SourceMapGuard().assessMapServed(false).safe, true)
})

test('directive not at file end flagged', () => {
  const text = '//# sourceMappingURL=a.js.map\nvar later=1;\nvar more=2;\nvar end=3;'
  const r = reasons({ kind: 'js', text: text, production: true })
  assert.ok(r.includes(SM2_REASON.COMMENT_IN_ODD_PLACE))
})
