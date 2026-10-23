'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { RTPClassify, RTP_CLASS, RTP_BLOCK, RTP_WARN, RTP_ALLOW } = require('./rtcsdpttokendirectoryguard.js')

test('RTP block classification', () => {
  for (const v of RTP_BLOCK) assert.equal(RTPClassify(v), RTP_CLASS.BLOCK, v)
})

test('RTP warn classification', () => {
  for (const v of RTP_WARN) assert.equal(RTPClassify(v), RTP_CLASS.WARN, v)
})

test('RTP allow classification', () => {
  for (const v of RTP_ALLOW) assert.equal(RTPClassify(v), RTP_CLASS.ALLOW, v)
})

test('RTP unknown classification', () => {
  assert.equal(RTPClassify('zzz-not-in-catalog-7'), RTP_CLASS.UNKNOWN)
})
