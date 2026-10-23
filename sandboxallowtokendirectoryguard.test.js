'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SATClassify, SAT_CLASS, SAT_BLOCK, SAT_WARN, SAT_ALLOW } = require('./sandboxallowtokendirectoryguard.js')

test('SAT block classification', () => {
  for (const v of SAT_BLOCK) assert.equal(SATClassify(v), SAT_CLASS.BLOCK, v)
})

test('SAT warn classification', () => {
  for (const v of SAT_WARN) assert.equal(SATClassify(v), SAT_CLASS.WARN, v)
})

test('SAT allow classification', () => {
  for (const v of SAT_ALLOW) assert.equal(SATClassify(v), SAT_CLASS.ALLOW, v)
})

test('SAT unknown classification', () => {
  assert.equal(SATClassify('zzz-not-in-catalog-7'), SAT_CLASS.UNKNOWN)
})
