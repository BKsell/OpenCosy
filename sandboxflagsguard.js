'use strict';

const REASON = {
  OK: 'ok',
  SANDBOX_OFF: 'sandbox-disabled',
  CONTEXT_ISOLATION_OFF: 'context-isolation-disabled',
  NODE_INTEGRATION_ON: 'node-integration-enabled',
  WEB_SECURITY_OFF: 'web-security-disabled',
  ALLOW_RUNNING_INSECURE: 'allow-running-insecure-content',
  REMOTE_MODULE_ON: 'remote-module-enabled',
  NO_SANDBOX_SWITCH: 'no-sandbox-switch',
};

const REQUIRED = {
  sandbox: true,
  contextIsolation: true,
  nodeIntegration: false,
  webSecurity: true,
  allowRunningInsecureContent: false,
  enableRemoteModule: false,
};

function evaluatePreferences(preferences, options) {
  const prefs = preferences || {};
  const opts = options || {};
  if (opts.shouldSandbox === false) {
    if (prefs.sandbox === true) return { ok: true, blocked: false, reason: REASON.OK, field: 'sandbox' };
    return { ok: true, blocked: false, reason: REASON.OK, field: 'sandbox', note: 'sandbox optional' };
  }
  if (prefs.sandbox === false || prefs.sandbox === undefined) {
    return { ok: false, blocked: true, reason: REASON.SANDBOX_OFF, field: 'sandbox', value: prefs.sandbox };
  }
  if (prefs.contextIsolation === false || prefs.contextIsolation === undefined) {
    return { ok: false, blocked: true, reason: REASON.CONTEXT_ISOLATION_OFF, field: 'contextIsolation', value: prefs.contextIsolation };
  }
  if (prefs.nodeIntegration === true) {
    return { ok: false, blocked: true, reason: REASON.NODE_INTEGRATION_ON, field: 'nodeIntegration' };
  }
  if (prefs.webSecurity === false) {
    return { ok: false, blocked: true, reason: REASON.WEB_SECURITY_OFF, field: 'webSecurity' };
  }
  if (prefs.allowRunningInsecureContent === true) {
    return { ok: false, blocked: true, reason: REASON.ALLOW_RUNNING_INSECURE, field: 'allowRunningInsecureContent' };
  }
  if (prefs.enableRemoteModule === true) {
    return { ok: false, blocked: true, reason: REASON.REMOTE_MODULE_ON, field: 'enableRemoteModule' };
  }
  return { ok: true, blocked: false, reason: REASON.OK, field: null };
}

function evaluateSwitchSet(switches) {
  const list = Array.isArray(switches) ? switches : [];
  const findings = [];
  let blocked = 0;
  const prefs = {};
  for (const raw of list) {
    if (typeof raw !== 'string') continue;
    const text = raw.trim().replace(/^--/, '');
    const eq = text.indexOf('=');
    const key = (eq >= 0 ? text.slice(0, eq) : text).toLowerCase();
    const value = eq >= 0 ? text.slice(eq + 1) : 'true';
    if (key === 'no-sandbox' || key === 'disable-web-security' || key === 'allow-running-insecure-content') {
      blocked += 1;
      findings.push({ reason: key === 'no-sandbox' ? REASON.NO_SANDBOX_SWITCH : REASON.WEB_SECURITY_OFF, field: key });
      continue;
    }
    if (key === 'enable-features' && value.includes('ElectronRemote')) {
      blocked += 1;
      findings.push({ reason: REASON.REMOTE_MODULE_ON, field: key });
    }
  }
  const prefsResult = evaluatePreferences(prefs, { shouldSandbox: blocked === 0 });
  if (prefsResult.blocked) {
    blocked += 1;
    findings.push({ reason: prefsResult.reason, field: prefsResult.field });
  }
  return { ok: blocked === 0, blocked: blocked > 0, reason: blocked > 0 ? findings[0].reason : REASON.OK, findings };
}

function auditSandboxBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluatePreferences(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ reason: result.reason, field: result.field });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no sandbox risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.field || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  REQUIRED,
  evaluatePreferences,
  evaluateSwitchSet,
  auditSandboxBatch,
  describeFindings,
};
