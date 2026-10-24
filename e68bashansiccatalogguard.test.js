'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68BSHClassify, E68BSH_CLASS, E68BSH_BLOCK, E68BSH_WARN, E68BSH_ALLOW } = require('./e68bashansiccatalogguard.js')

test('E68BSH block classification', () => {
  for (const v of E68BSH_BLOCK) assert.equal(E68BSHClassify(v), E68BSH_CLASS.BLOCK, v)
})

test('E68BSH warn classification', () => {
  for (const v of E68BSH_WARN) assert.equal(E68BSHClassify(v), E68BSH_CLASS.WARN, v)
})

test('E68BSH allow classification', () => {
  for (const v of E68BSH_ALLOW) assert.equal(E68BSHClassify(v), E68BSH_CLASS.ALLOW, v)
})

test('E68BSH unknown classification', () => {
  assert.equal(E68BSHClassify('zzz-not-in-any-e68-catalog-77'), E68BSH_CLASS.UNKNOWN)
})
