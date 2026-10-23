'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CloudMetadataGuard, CM_REASON } = require('./cloudmetadataguard.js')

function reasons (input) {
  return new CloudMetadataGuard().evaluate(input).findings.map((f) => f.reason)
}

test('ordinary host safe', () => {
  assert.equal(new CloudMetadataGuard().evaluate({ host: 'api.example.com', path: '/v1' }).safe, true)
})

test('link-local metadata ip flagged', () => {
  assert.ok(reasons({ host: '169.254.169.254', path: '/latest/meta-data/' }).includes(CM_REASON.LINKLOCAL_METADATA_IP))
})

test('gcp metadata hostname flagged', () => {
  assert.ok(reasons({ host: 'metadata.google.internal', path: '/computeMetadata/v1/' }).includes(CM_REASON.METADATA_HOSTNAME))
})

test('metadata path flagged', () => {
  assert.ok(reasons({ host: '10.0.0.9', path: '/metadata/instance?api-version=2021' }).includes(CM_REASON.METADATA_PATH))
})

test('aws iam path flagged', () => {
  assert.ok(reasons({ host: '169.254.169.254', path: '/latest/meta-data/iam/security-credentials/' }).length >= 2)
})

test('metadata spoof header flagged', () => {
  const r = reasons({
    host: '10.0.0.9',
    path: '/x',
    headers: [{ name: 'Metadata', value: 'true' }]
  })
  assert.ok(r.includes(CM_REASON.METADATA_SPOOF_HEADER))
})

test('aws imdsv2 token header flagged', () => {
  const r = reasons({
    host: '169.254.169.254',
    path: '/latest/api/token',
    headers: [{ name: 'X-aws-ec2-metadata-token-ttl-seconds', value: '21600' }]
  })
  // 该头不在白名单，不应误报 SPOOF；但主机位仍报 linklocal
  assert.ok(r.includes(CM_REASON.LINKLOCAL_METADATA_IP))
})

test('header name case-insensitive', () => {
  const r = reasons({ host: 'h', path: '/p', headers: [{ name: 'METADATA-FLAVOR', value: 'Google' }] })
  assert.ok(r.includes(CM_REASON.METADATA_SPOOF_HEADER))
})
