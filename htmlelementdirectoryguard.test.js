'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { HTDClassify, HTD_CLASS, HTD_BLOCK, HTD_WARN, HTD_ALLOW } = require('./htmlelementdirectoryguard.js')

test('HTD block classification', () => {
  for (const v of HTD_BLOCK) assert.equal(HTDClassify(v), HTD_CLASS.BLOCK, v)
})

test('HTD warn classification', () => {
  for (const v of HTD_WARN) assert.equal(HTDClassify(v), HTD_CLASS.WARN, v)
})

test('HTD allow classification', () => {
  for (const v of HTD_ALLOW) assert.equal(HTDClassify(v), HTD_CLASS.ALLOW, v)
})

test('HTD unknown classification', () => {
  assert.equal(HTDClassify('zzz-not-in-catalog-7'), HTD_CLASS.UNKNOWN)
})
