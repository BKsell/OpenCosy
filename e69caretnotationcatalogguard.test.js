'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69CARClassify, E69CAR_CLASS, E69CAR_BLOCK, E69CAR_WARN, E69CAR_ALLOW } = require('./e69caretnotationcatalogguard.js')

test('E69CAR block classification', () => {
  for (const v of E69CAR_BLOCK) assert.equal(E69CARClassify(v), E69CAR_CLASS.BLOCK, v)
})

test('E69CAR warn classification', () => {
  for (const v of E69CAR_WARN) assert.equal(E69CARClassify(v), E69CAR_CLASS.WARN, v)
})

test('E69CAR allow classification', () => {
  for (const v of E69CAR_ALLOW) assert.equal(E69CARClassify(v), E69CAR_CLASS.ALLOW, v)
})

test('E69CAR unknown classification', () => {
  assert.equal(E69CARClassify('zzz-not-in-any-e69-catalog-88'), E69CAR_CLASS.UNKNOWN)
})
