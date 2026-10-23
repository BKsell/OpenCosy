'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { BTHClassify, BTH_CLASS, BTH_BLOCK, BTH_WARN, BTH_ALLOW } = require('./bluetoothgenericdescriptorcatalogguard.js')

test('BTH block classification', () => {
  for (const v of BTH_BLOCK) assert.equal(BTHClassify(v), BTH_CLASS.BLOCK, v)
})

test('BTH warn classification', () => {
  for (const v of BTH_WARN) assert.equal(BTHClassify(v), BTH_CLASS.WARN, v)
})

test('BTH allow classification', () => {
  for (const v of BTH_ALLOW) assert.equal(BTHClassify(v), BTH_CLASS.ALLOW, v)
})

test('BTH unknown classification', () => {
  assert.equal(BTHClassify('zzz-not-in-catalog-7'), BTH_CLASS.UNKNOWN)
})
