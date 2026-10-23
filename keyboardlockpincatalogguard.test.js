'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { KBDClassify, KBD_CLASS, KBD_BLOCK, KBD_WARN, KBD_ALLOW } = require('./keyboardlockpincatalogguard.js')

test('KBD block classification', () => {
  for (const v of KBD_BLOCK) assert.equal(KBDClassify(v), KBD_CLASS.BLOCK, v)
})

test('KBD warn classification', () => {
  for (const v of KBD_WARN) assert.equal(KBDClassify(v), KBD_CLASS.WARN, v)
})

test('KBD allow classification', () => {
  for (const v of KBD_ALLOW) assert.equal(KBDClassify(v), KBD_CLASS.ALLOW, v)
})

test('KBD unknown classification', () => {
  assert.equal(KBDClassify('zzz-not-in-catalog-7'), KBD_CLASS.UNKNOWN)
})
