'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70LPUClassify, E70LPU_CLASS, E70LPU_BLOCK, E70LPU_WARN, E70LPU_ALLOW } = require('./e70legacypctucatalogguard.js')

test('E70LPU block classification', () => {
  for (const v of E70LPU_BLOCK) assert.equal(E70LPUClassify(v), E70LPU_CLASS.BLOCK, v)
})

test('E70LPU warn classification', () => {
  for (const v of E70LPU_WARN) assert.equal(E70LPUClassify(v), E70LPU_CLASS.WARN, v)
})

test('E70LPU allow classification', () => {
  for (const v of E70LPU_ALLOW) assert.equal(E70LPUClassify(v), E70LPU_CLASS.ALLOW, v)
})

test('E70LPU unknown classification', () => {
  assert.equal(E70LPUClassify('zzz-not-in-any-e70-catalog-99'), E70LPU_CLASS.UNKNOWN)
})
