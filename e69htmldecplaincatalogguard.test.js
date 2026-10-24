'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69HDPClassify, E69HDP_CLASS, E69HDP_BLOCK, E69HDP_WARN, E69HDP_ALLOW } = require('./e69htmldecplaincatalogguard.js')

test('E69HDP block classification', () => {
  for (const v of E69HDP_BLOCK) assert.equal(E69HDPClassify(v), E69HDP_CLASS.BLOCK, v)
})

test('E69HDP warn classification', () => {
  for (const v of E69HDP_WARN) assert.equal(E69HDPClassify(v), E69HDP_CLASS.WARN, v)
})

test('E69HDP allow classification', () => {
  for (const v of E69HDP_ALLOW) assert.equal(E69HDPClassify(v), E69HDP_CLASS.ALLOW, v)
})

test('E69HDP unknown classification', () => {
  assert.equal(E69HDPClassify('zzz-not-in-any-e69-catalog-88'), E69HDP_CLASS.UNKNOWN)
})
