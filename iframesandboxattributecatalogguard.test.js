'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { IFAClassify, IFA_CLASS, IFA_BLOCK, IFA_WARN, IFA_ALLOW } = require('./iframesandboxattributecatalogguard.js')

test('IFA block classification', () => {
  for (const v of IFA_BLOCK) assert.equal(IFAClassify(v), IFA_CLASS.BLOCK, v)
})

test('IFA warn classification', () => {
  for (const v of IFA_WARN) assert.equal(IFAClassify(v), IFA_CLASS.WARN, v)
})

test('IFA allow classification', () => {
  for (const v of IFA_ALLOW) assert.equal(IFAClassify(v), IFA_CLASS.ALLOW, v)
})

test('IFA unknown classification', () => {
  assert.equal(IFAClassify('zzz-not-in-catalog-7'), IFA_CLASS.UNKNOWN)
})
