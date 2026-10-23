'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { AFNClassify, AFN_CLASS, AFN_BLOCK, AFN_WARN, AFN_ALLOW } = require('./autofillfieldnamedirectoryguard.js')

test('AFN block classification', () => {
  for (const v of AFN_BLOCK) assert.equal(AFNClassify(v), AFN_CLASS.BLOCK, v)
})

test('AFN warn classification', () => {
  for (const v of AFN_WARN) assert.equal(AFNClassify(v), AFN_CLASS.WARN, v)
})

test('AFN allow classification', () => {
  for (const v of AFN_ALLOW) assert.equal(AFNClassify(v), AFN_CLASS.ALLOW, v)
})

test('AFN unknown classification', () => {
  assert.equal(AFNClassify('zzz-not-in-catalog-7'), AFN_CLASS.UNKNOWN)
})
