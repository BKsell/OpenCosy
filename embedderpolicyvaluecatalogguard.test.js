'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { EPVClassify, EPV_CLASS, EPV_BLOCK, EPV_WARN, EPV_ALLOW } = require('./embedderpolicyvaluecatalogguard.js')

test('EPV block classification', () => {
  for (const v of EPV_BLOCK) assert.equal(EPVClassify(v), EPV_CLASS.BLOCK, v)
})

test('EPV warn classification', () => {
  for (const v of EPV_WARN) assert.equal(EPVClassify(v), EPV_CLASS.WARN, v)
})

test('EPV allow classification', () => {
  for (const v of EPV_ALLOW) assert.equal(EPVClassify(v), EPV_CLASS.ALLOW, v)
})

test('EPV unknown classification', () => {
  assert.equal(EPVClassify('zzz-not-in-catalog-7'), EPV_CLASS.UNKNOWN)
})
