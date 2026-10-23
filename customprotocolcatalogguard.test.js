'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CSHClassify, CSH_CLASS, CSH_BLOCK, CSH_WARN, CSH_ALLOW } = require('./customprotocolcatalogguard.js')

test('CSH block classification', () => {
  for (const v of CSH_BLOCK) assert.equal(CSHClassify(v), CSH_CLASS.BLOCK, v)
})

test('CSH warn classification', () => {
  for (const v of CSH_WARN) assert.equal(CSHClassify(v), CSH_CLASS.WARN, v)
})

test('CSH allow classification', () => {
  for (const v of CSH_ALLOW) assert.equal(CSHClassify(v), CSH_CLASS.ALLOW, v)
})

test('CSH unknown classification', () => {
  assert.equal(CSHClassify('zzz-not-in-catalog-7'), CSH_CLASS.UNKNOWN)
})
