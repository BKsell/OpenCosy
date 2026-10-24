'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68BGLClassify, E68BGL_CLASS, E68BGL_BLOCK, E68BGL_WARN, E68BGL_ALLOW } = require('./e68bigu32lowercatalogguard.js')

test('E68BGL block classification', () => {
  for (const v of E68BGL_BLOCK) assert.equal(E68BGLClassify(v), E68BGL_CLASS.BLOCK, v)
})

test('E68BGL warn classification', () => {
  for (const v of E68BGL_WARN) assert.equal(E68BGLClassify(v), E68BGL_CLASS.WARN, v)
})

test('E68BGL allow classification', () => {
  for (const v of E68BGL_ALLOW) assert.equal(E68BGLClassify(v), E68BGL_CLASS.ALLOW, v)
})

test('E68BGL unknown classification', () => {
  assert.equal(E68BGLClassify('zzz-not-in-any-e68-catalog-77'), E68BGL_CLASS.UNKNOWN)
})
