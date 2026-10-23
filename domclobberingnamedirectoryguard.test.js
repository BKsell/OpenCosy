'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { DCNClassify, DCN_CLASS, DCN_BLOCK, DCN_WARN, DCN_ALLOW } = require('./domclobberingnamedirectoryguard.js')

test('DCN block classification', () => {
  for (const v of DCN_BLOCK) assert.equal(DCNClassify(v), DCN_CLASS.BLOCK, v)
})

test('DCN warn classification', () => {
  for (const v of DCN_WARN) assert.equal(DCNClassify(v), DCN_CLASS.WARN, v)
})

test('DCN allow classification', () => {
  for (const v of DCN_ALLOW) assert.equal(DCNClassify(v), DCN_CLASS.ALLOW, v)
})

test('DCN unknown classification', () => {
  assert.equal(DCNClassify('zzz-not-in-catalog-7'), DCN_CLASS.UNKNOWN)
})
