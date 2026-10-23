'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { FENClassify, FEN_CLASS, FEN_BLOCK, FEN_WARN, FEN_ALLOW } = require('./fontenumerationcatalogguard.js')

test('FEN block classification', () => {
  for (const v of FEN_BLOCK) assert.equal(FENClassify(v), FEN_CLASS.BLOCK, v)
})

test('FEN warn classification', () => {
  for (const v of FEN_WARN) assert.equal(FENClassify(v), FEN_CLASS.WARN, v)
})

test('FEN allow classification', () => {
  for (const v of FEN_ALLOW) assert.equal(FENClassify(v), FEN_CLASS.ALLOW, v)
})

test('FEN unknown classification', () => {
  assert.equal(FENClassify('zzz-not-in-catalog-7'), FEN_CLASS.UNKNOWN)
})
