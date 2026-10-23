'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { IMGClassify, IMG_CLASS, IMG_BLOCK, IMG_WARN, IMG_ALLOW } = require('./imagetrackingpixelcatalogguard.js')

test('IMG block classification', () => {
  for (const v of IMG_BLOCK) assert.equal(IMGClassify(v), IMG_CLASS.BLOCK, v)
})

test('IMG warn classification', () => {
  for (const v of IMG_WARN) assert.equal(IMGClassify(v), IMG_CLASS.WARN, v)
})

test('IMG allow classification', () => {
  for (const v of IMG_ALLOW) assert.equal(IMGClassify(v), IMG_CLASS.ALLOW, v)
})

test('IMG unknown classification', () => {
  assert.equal(IMGClassify('zzz-not-in-catalog-7'), IMG_CLASS.UNKNOWN)
})
