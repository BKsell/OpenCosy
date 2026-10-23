'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { IHSClassify, IHS_CLASS, IHS_BLOCK, IHS_WARN, IHS_ALLOW } = require('./innerhtmlsinkcatalogguard.js')

test('IHS block classification', () => {
  for (const v of IHS_BLOCK) assert.equal(IHSClassify(v), IHS_CLASS.BLOCK, v)
})

test('IHS warn classification', () => {
  for (const v of IHS_WARN) assert.equal(IHSClassify(v), IHS_CLASS.WARN, v)
})

test('IHS allow classification', () => {
  for (const v of IHS_ALLOW) assert.equal(IHSClassify(v), IHS_CLASS.ALLOW, v)
})

test('IHS unknown classification', () => {
  assert.equal(IHSClassify('zzz-not-in-catalog-7'), IHS_CLASS.UNKNOWN)
})
