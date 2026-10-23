'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WADClassify, WAD_CLASS, WAD_BLOCK, WAD_WARN, WAD_ALLOW } = require('./webapiinterfacedirectoryguard.js')

test('WAD block classification', () => {
  for (const v of WAD_BLOCK) assert.equal(WADClassify(v), WAD_CLASS.BLOCK, v)
})

test('WAD warn classification', () => {
  for (const v of WAD_WARN) assert.equal(WADClassify(v), WAD_CLASS.WARN, v)
})

test('WAD allow classification', () => {
  for (const v of WAD_ALLOW) assert.equal(WADClassify(v), WAD_CLASS.ALLOW, v)
})

test('WAD unknown classification', () => {
  assert.equal(WADClassify('zzz-not-in-catalog-7'), WAD_CLASS.UNKNOWN)
})
