'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68H3PClassify, E68H3P_CLASS, E68H3P_BLOCK, E68H3P_WARN, E68H3P_ALLOW } = require('./e68htmldec3padcatalogguard.js')

test('E68H3P block classification', () => {
  for (const v of E68H3P_BLOCK) assert.equal(E68H3PClassify(v), E68H3P_CLASS.BLOCK, v)
})

test('E68H3P warn classification', () => {
  for (const v of E68H3P_WARN) assert.equal(E68H3PClassify(v), E68H3P_CLASS.WARN, v)
})

test('E68H3P allow classification', () => {
  for (const v of E68H3P_ALLOW) assert.equal(E68H3PClassify(v), E68H3P_CLASS.ALLOW, v)
})

test('E68H3P unknown classification', () => {
  assert.equal(E68H3PClassify('zzz-not-in-any-e68-catalog-77'), E68H3P_CLASS.UNKNOWN)
})
