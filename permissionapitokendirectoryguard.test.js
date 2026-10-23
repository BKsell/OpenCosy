'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { PATClassify, PAT_CLASS, PAT_BLOCK, PAT_WARN, PAT_ALLOW } = require('./permissionapitokendirectoryguard.js')

test('PAT block classification', () => {
  for (const v of PAT_BLOCK) assert.equal(PATClassify(v), PAT_CLASS.BLOCK, v)
})

test('PAT warn classification', () => {
  for (const v of PAT_WARN) assert.equal(PATClassify(v), PAT_CLASS.WARN, v)
})

test('PAT allow classification', () => {
  for (const v of PAT_ALLOW) assert.equal(PATClassify(v), PAT_CLASS.ALLOW, v)
})

test('PAT unknown classification', () => {
  assert.equal(PATClassify('zzz-not-in-catalog-7'), PAT_CLASS.UNKNOWN)
})
