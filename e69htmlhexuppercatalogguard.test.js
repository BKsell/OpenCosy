'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69HHUClassify, E69HHU_CLASS, E69HHU_BLOCK, E69HHU_WARN, E69HHU_ALLOW } = require('./e69htmlhexuppercatalogguard.js')

test('E69HHU block classification', () => {
  for (const v of E69HHU_BLOCK) assert.equal(E69HHUClassify(v), E69HHU_CLASS.BLOCK, v)
})

test('E69HHU warn classification', () => {
  for (const v of E69HHU_WARN) assert.equal(E69HHUClassify(v), E69HHU_CLASS.WARN, v)
})

test('E69HHU allow classification', () => {
  for (const v of E69HHU_ALLOW) assert.equal(E69HHUClassify(v), E69HHU_CLASS.ALLOW, v)
})

test('E69HHU unknown classification', () => {
  assert.equal(E69HHUClassify('zzz-not-in-any-e69-catalog-88'), E69HHU_CLASS.UNKNOWN)
})
