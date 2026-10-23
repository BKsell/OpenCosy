'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { PMHClassify, PMH_CLASS, PMH_BLOCK, PMH_WARN, PMH_ALLOW } = require('./messagehandlernoorigincatalogguard.js')

test('PMH block classification', () => {
  for (const v of PMH_BLOCK) assert.equal(PMHClassify(v), PMH_CLASS.BLOCK, v)
})

test('PMH warn classification', () => {
  for (const v of PMH_WARN) assert.equal(PMHClassify(v), PMH_CLASS.WARN, v)
})

test('PMH allow classification', () => {
  for (const v of PMH_ALLOW) assert.equal(PMHClassify(v), PMH_CLASS.ALLOW, v)
})

test('PMH unknown classification', () => {
  assert.equal(PMHClassify('zzz-not-in-catalog-7'), PMH_CLASS.UNKNOWN)
})
