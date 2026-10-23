'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { PQNClassify, PQN_CLASS, PQN_BLOCK, PQN_WARN, PQN_ALLOW } = require('./permissionnamecatalogguard.js')

test('PQN block classification', () => {
  for (const v of PQN_BLOCK) assert.equal(PQNClassify(v), PQN_CLASS.BLOCK, v)
})

test('PQN warn classification', () => {
  for (const v of PQN_WARN) assert.equal(PQNClassify(v), PQN_CLASS.WARN, v)
})

test('PQN allow classification', () => {
  for (const v of PQN_ALLOW) assert.equal(PQNClassify(v), PQN_CLASS.ALLOW, v)
})

test('PQN unknown classification', () => {
  assert.equal(PQNClassify('zzz-not-in-catalog-7'), PQN_CLASS.UNKNOWN)
})
