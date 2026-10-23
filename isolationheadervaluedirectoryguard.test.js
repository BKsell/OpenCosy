'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { IHVClassify, IHV_CLASS, IHV_BLOCK, IHV_WARN, IHV_ALLOW } = require('./isolationheadervaluedirectoryguard.js')

test('IHV block classification', () => {
  for (const v of IHV_BLOCK) assert.equal(IHVClassify(v), IHV_CLASS.BLOCK, v)
})

test('IHV warn classification', () => {
  for (const v of IHV_WARN) assert.equal(IHVClassify(v), IHV_CLASS.WARN, v)
})

test('IHV allow classification', () => {
  for (const v of IHV_ALLOW) assert.equal(IHVClassify(v), IHV_CLASS.ALLOW, v)
})

test('IHV unknown classification', () => {
  assert.equal(IHVClassify('zzz-not-in-catalog-7'), IHV_CLASS.UNKNOWN)
})
