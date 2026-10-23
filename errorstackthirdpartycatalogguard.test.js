'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { ERLClassify, ERL_CLASS, ERL_BLOCK, ERL_WARN, ERL_ALLOW } = require('./errorstackthirdpartycatalogguard.js')

test('ERL block classification', () => {
  for (const v of ERL_BLOCK) assert.equal(ERLClassify(v), ERL_CLASS.BLOCK, v)
})

test('ERL warn classification', () => {
  for (const v of ERL_WARN) assert.equal(ERLClassify(v), ERL_CLASS.WARN, v)
})

test('ERL allow classification', () => {
  for (const v of ERL_ALLOW) assert.equal(ERLClassify(v), ERL_CLASS.ALLOW, v)
})

test('ERL unknown classification', () => {
  assert.equal(ERLClassify('zzz-not-in-catalog-7'), ERL_CLASS.UNKNOWN)
})
