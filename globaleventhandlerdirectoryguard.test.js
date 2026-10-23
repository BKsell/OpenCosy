'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { GEHClassify, GEH_CLASS, GEH_BLOCK, GEH_WARN, GEH_ALLOW } = require('./globaleventhandlerdirectoryguard.js')

test('GEH block classification', () => {
  for (const v of GEH_BLOCK) assert.equal(GEHClassify(v), GEH_CLASS.BLOCK, v)
})

test('GEH warn classification', () => {
  for (const v of GEH_WARN) assert.equal(GEHClassify(v), GEH_CLASS.WARN, v)
})

test('GEH allow classification', () => {
  for (const v of GEH_ALLOW) assert.equal(GEHClassify(v), GEH_CLASS.ALLOW, v)
})

test('GEH unknown classification', () => {
  assert.equal(GEHClassify('zzz-not-in-catalog-7'), GEH_CLASS.UNKNOWN)
})
