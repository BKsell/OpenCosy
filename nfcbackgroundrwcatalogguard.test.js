'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { NFBClassify, NFB_CLASS, NFB_BLOCK, NFB_WARN, NFB_ALLOW } = require('./nfcbackgroundrwcatalogguard.js')

test('NFB block classification', () => {
  for (const v of NFB_BLOCK) assert.equal(NFBClassify(v), NFB_CLASS.BLOCK, v)
})

test('NFB warn classification', () => {
  for (const v of NFB_WARN) assert.equal(NFBClassify(v), NFB_CLASS.WARN, v)
})

test('NFB allow classification', () => {
  for (const v of NFB_ALLOW) assert.equal(NFBClassify(v), NFB_CLASS.ALLOW, v)
})

test('NFB unknown classification', () => {
  assert.equal(NFBClassify('zzz-not-in-catalog-7'), NFB_CLASS.UNKNOWN)
})
