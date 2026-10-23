'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { MDIClassify, MDI_CLASS, MDI_BLOCK, MDI_WARN, MDI_ALLOW } = require('./midisysexcatalogguard.js')

test('MDI block classification', () => {
  for (const v of MDI_BLOCK) assert.equal(MDIClassify(v), MDI_CLASS.BLOCK, v)
})

test('MDI warn classification', () => {
  for (const v of MDI_WARN) assert.equal(MDIClassify(v), MDI_CLASS.WARN, v)
})

test('MDI allow classification', () => {
  for (const v of MDI_ALLOW) assert.equal(MDIClassify(v), MDI_CLASS.ALLOW, v)
})

test('MDI unknown classification', () => {
  assert.equal(MDIClassify('zzz-not-in-catalog-7'), MDI_CLASS.UNKNOWN)
})
