'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { IEHClassify, IEH_CLASS, IEH_BLOCK, IEH_WARN, IEH_ALLOW } = require('./inlineeventhandlernamescatalogguard.js')

test('IEH block classification', () => {
  for (const v of IEH_BLOCK) assert.equal(IEHClassify(v), IEH_CLASS.BLOCK, v)
})

test('IEH warn classification', () => {
  for (const v of IEH_WARN) assert.equal(IEHClassify(v), IEH_CLASS.WARN, v)
})

test('IEH allow classification', () => {
  for (const v of IEH_ALLOW) assert.equal(IEHClassify(v), IEH_CLASS.ALLOW, v)
})

test('IEH unknown classification', () => {
  assert.equal(IEHClassify('zzz-not-in-catalog-7'), IEH_CLASS.UNKNOWN)
})
