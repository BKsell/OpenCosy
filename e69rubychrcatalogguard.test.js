'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69RBCClassify, E69RBC_CLASS, E69RBC_BLOCK, E69RBC_WARN, E69RBC_ALLOW } = require('./e69rubychrcatalogguard.js')

test('E69RBC block classification', () => {
  for (const v of E69RBC_BLOCK) assert.equal(E69RBCClassify(v), E69RBC_CLASS.BLOCK, v)
})

test('E69RBC warn classification', () => {
  for (const v of E69RBC_WARN) assert.equal(E69RBCClassify(v), E69RBC_CLASS.WARN, v)
})

test('E69RBC allow classification', () => {
  for (const v of E69RBC_ALLOW) assert.equal(E69RBCClassify(v), E69RBC_CLASS.ALLOW, v)
})

test('E69RBC unknown classification', () => {
  assert.equal(E69RBCClassify('zzz-not-in-any-e69-catalog-88'), E69RBC_CLASS.UNKNOWN)
})
