'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { BSHClassify, BSH_CLASS, BSH_BLOCK, BSH_WARN, BSH_ALLOW } = require('./basehrefinjectioncatalogguard.js')

test('BSH block classification', () => {
  for (const v of BSH_BLOCK) assert.equal(BSHClassify(v), BSH_CLASS.BLOCK, v)
})

test('BSH warn classification', () => {
  for (const v of BSH_WARN) assert.equal(BSHClassify(v), BSH_CLASS.WARN, v)
})

test('BSH allow classification', () => {
  for (const v of BSH_ALLOW) assert.equal(BSHClassify(v), BSH_CLASS.ALLOW, v)
})

test('BSH unknown classification', () => {
  assert.equal(BSHClassify('zzz-not-in-catalog-7'), BSH_CLASS.UNKNOWN)
})
