'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68HXUClassify, E68HXU_CLASS, E68HXU_BLOCK, E68HXU_WARN, E68HXU_ALLOW } = require('./e68hexbraceuppercatalogguard.js')

test('E68HXU block classification', () => {
  for (const v of E68HXU_BLOCK) assert.equal(E68HXUClassify(v), E68HXU_CLASS.BLOCK, v)
})

test('E68HXU warn classification', () => {
  for (const v of E68HXU_WARN) assert.equal(E68HXUClassify(v), E68HXU_CLASS.WARN, v)
})

test('E68HXU allow classification', () => {
  for (const v of E68HXU_ALLOW) assert.equal(E68HXUClassify(v), E68HXU_CLASS.ALLOW, v)
})

test('E68HXU unknown classification', () => {
  assert.equal(E68HXUClassify('zzz-not-in-any-e68-catalog-77'), E68HXU_CLASS.UNKNOWN)
})
