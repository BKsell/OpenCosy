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
  switchguard: ['SEVERITY_CRITICAL', 'auditSwitches', 'collectSources'],
  hoverguard: ['createHoverState', 'decideHoverUrl', 'describeHoverReason', 'resetForNavigation',
    'HOVER_SHOW', 'HOVER_DROP', 'DROP_FLOOD'],
  childwindowguard: ['createChildWindowState', 'evaluateChildWindow', 'resetForNavigation',
    'CHILD_ALLOW', 'CHILD_CLOSE', 'CHILD_ISOLATE'],
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

test('switchguard blocks security-disabling launch switches', () => {
  const guard = require('./switchguard');
  const audit = guard.auditSwitches(guard.collectSources({
    argv: ['cosy.exe', '/app', '--disable-web-security'],
    env: { ELECTRON_EXTRA_LAUNCH_ARGS: '--no-sandbox' },
  }));
  assert.equal(audit.hasCritical, true);
  assert.deepEqual(audit.criticalFlags.map((f) => f.raw).sort(),
    ['--disable-web-security', '--no-sandbox']);
  assert.equal(guard.auditSwitches(guard.collectSources({ argv: ['cosy.exe', '/app'], env: {} })).hasCritical, false);
});

test('hoverguard throttles and resets hover previews', () => {
  const guard = require('./hoverguard');
  const state = guard.createHoverState();
  assert.equal(guard.decideHoverUrl(state, 'https://example.com/a', 1000).action, guard.HOVER_SHOW);
  assert.equal(guard.decideHoverUrl(state, 'https://example.com/a', 1001).action, guard.HOVER_HOLD);
  guard.resetForNavigation(state);
  assert.equal(state.times.length, 0);
});

test('childwindowguard closes dangerous child schemes', () => {
  const guard = require('./childwindowguard');
  const verdict = guard.evaluateChildWindow(
    { url: 'javascript:alert(1)', prefs: {}, openerPresent: true },
    guard.createChildWindowState(), 1000);
  assert.equal(verdict.action, guard.CHILD_CLOSE);
});
