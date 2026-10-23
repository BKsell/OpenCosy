'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SCRClassify, SCR_CLASS, SCR_BLOCK, SCR_WARN, SCR_ALLOW } = require('./screencapturesystemaudiocatalogguard.js')

test('SCR block classification', () => {
  for (const v of SCR_BLOCK) assert.equal(SCRClassify(v), SCR_CLASS.BLOCK, v)
})

test('SCR warn classification', () => {
  for (const v of SCR_WARN) assert.equal(SCRClassify(v), SCR_CLASS.WARN, v)
})

test('SCR allow classification', () => {
  for (const v of SCR_ALLOW) assert.equal(SCRClassify(v), SCR_CLASS.ALLOW, v)
})

test('SCR unknown classification', () => {
  assert.equal(SCRClassify('zzz-not-in-catalog-7'), SCR_CLASS.UNKNOWN)
})
