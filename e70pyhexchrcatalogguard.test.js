'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70PHXClassify, E70PHX_CLASS, E70PHX_BLOCK, E70PHX_WARN, E70PHX_ALLOW } = require('./e70pyhexchrcatalogguard.js')

test('E70PHX block classification', () => {
  for (const v of E70PHX_BLOCK) assert.equal(E70PHXClassify(v), E70PHX_CLASS.BLOCK, v)
})

test('E70PHX warn classification', () => {
  for (const v of E70PHX_WARN) assert.equal(E70PHXClassify(v), E70PHX_CLASS.WARN, v)
})

test('E70PHX allow classification', () => {
  for (const v of E70PHX_ALLOW) assert.equal(E70PHXClassify(v), E70PHX_CLASS.ALLOW, v)
})

test('E70PHX unknown classification', () => {
  assert.equal(E70PHXClassify('zzz-not-in-any-e70-catalog-99'), E70PHX_CLASS.UNKNOWN)
})
