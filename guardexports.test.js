'use strict';

const test = require('node:test');
const assert = require('node:assert');

const API = {
  fpguard: ['createFingerprintLedger', 'hostOf', 'normalizeWebRtcMode', 'resolveWebRtcPolicy',
    'sanitizeOutboundHeaders', 'stripAcceptClientHints', 'isHyperlinkPing', 'WEBRTC_POLICIES',
    'DEFAULT_WEBRTC_POLICY'],
  inputguard: ['asPlainObject', 'measureObject', 'assertShape', 'asString', 'asUrl'],
  shellguard: ['reviewLocalLaunchPath', 'reviewExternalUrl', 'describeReason'],
  dohguard: ['normalizeMode', 'KNOWN_PROVIDERS', 'SECURE_DNS_MODES', 'DEFAULT_MODE',
    'validateDohServer', 'resolveControls', 'getProviderById', 'createDohLedger'],
  certguard: ['sanitizeExceptionRecord', 'createException', 'normalizeHost', 'normalizeFingerprint',
    'classifyCertError', 'exceptionMatches', 'shortFingerprint', 'errorInfo', 'HARD_DENY_CODES'],
  deeplinkguard: ['reviewStartupArg', 'describeReason', 'pickDeepLinkFromArgv'],
};

for (const [modName, names] of Object.entries(API)) {
  test(`${modName} exports the API main.js injects`, () => {
    const mod = require(`./${modName}`);
    const missing = names.filter((n) => mod[n] === undefined);
    assert.deepEqual(missing, []);
  });
}

test('shellguard rejects non-allowlisted external schemes', () => {
  const shell = require('./shellguard');
  const review = shell.reviewExternalUrl('javascript:alert(1)', ['mailto', 'tel', 'https']);
  assert.equal(review.ok, false);
  assert.equal(shell.describeReason(review.reason).length > 0, true);
});

test('deeplinkguard resolves startup args end to end', () => {
  const guard = require('./deeplinkguard');
  const link = guard.pickDeepLinkFromArgv(['cosy.exe', '--x', 'https://example.com/a']);
  assert.equal(link.ok, true);
  assert.equal(guard.reviewStartupArg('cosy://evil/x').reason, 'host');
  assert.equal(guard.describeReason('host'), '内部深链主机不在白名单');
});
