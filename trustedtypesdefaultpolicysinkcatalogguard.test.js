'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { TTSClassify, TTS_CLASS, TTS_BLOCK, TTS_WARN, TTS_ALLOW } = require('./trustedtypesdefaultpolicysinkcatalogguard.js')

test('TTS block classification', () => {
  for (const v of TTS_BLOCK) assert.equal(TTSClassify(v), TTS_CLASS.BLOCK, v)
})

test('TTS warn classification', () => {
  for (const v of TTS_WARN) assert.equal(TTSClassify(v), TTS_CLASS.WARN, v)
})

test('TTS allow classification', () => {
  for (const v of TTS_ALLOW) assert.equal(TTSClassify(v), TTS_CLASS.ALLOW, v)
})

test('TTS unknown classification', () => {
  assert.equal(TTSClassify('zzz-not-in-catalog-7'), TTS_CLASS.UNKNOWN)
})
