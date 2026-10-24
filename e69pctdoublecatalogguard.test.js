'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69PDBClassify, E69PDB_CLASS, E69PDB_BLOCK, E69PDB_WARN, E69PDB_ALLOW } = require('./e69pctdoublecatalogguard.js')

test('E69PDB block classification', () => {
  for (const v of E69PDB_BLOCK) assert.equal(E69PDBClassify(v), E69PDB_CLASS.BLOCK, v)
})

test('E69PDB warn classification', () => {
  for (const v of E69PDB_WARN) assert.equal(E69PDBClassify(v), E69PDB_CLASS.WARN, v)
})

test('E69PDB allow classification', () => {
  for (const v of E69PDB_ALLOW) assert.equal(E69PDBClassify(v), E69PDB_CLASS.ALLOW, v)
})

test('E69PDB unknown classification', () => {
  assert.equal(E69PDBClassify('zzz-not-in-any-e69-catalog-88'), E69PDB_CLASS.UNKNOWN)
})
