'use strict';

const REASON = {
  OK: 'ok',
  CLOUD_PROVIDER: 'spellcheck-cloud-provider',
  REMOTE_DICTIONARY: 'spellcheck-remote-dictionary',
  INSECURE_ENDPOINT: 'spellcheck-insecure-endpoint',
  CREDENTIALS: 'spellcheck-endpoint-credentials',
  UNKNOWN_PROVIDER: 'spellcheck-unknown-provider',
};

const LOCAL_PROVIDERS = new Set(['hunspell', 'local', 'builtin', 'native']);
const BLOCKED_PROVIDERS = new Set(['google', 'cloud', 'remote', 'server']);
const MAX_ENDPOINT = 8192;

function evaluateSpellcheck(config) {
  const cfg = config || {};
  const provider = String(cfg.provider || 'local').toLowerCase();
  if (BLOCKED_PROVIDERS.has(provider)) {
    return { ok: false, blocked: true, reason: REASON.CLOUD_PROVIDER, provider };
  }
  if (!LOCAL_PROVIDERS.has(provider)) {
    return { ok: false, blocked: true, reason: REASON.UNKNOWN_PROVIDER, provider };
  }
  if (cfg.dictionaryUrl) {
    if (typeof cfg.dictionaryUrl !== 'string' || cfg.dictionaryUrl.length > MAX_ENDPOINT) {
      return { ok: false, blocked: true, reason: REASON.REMOTE_DICTIONARY, provider };
    }
    let url;
    try {
      url = new URL(cfg.dictionaryUrl);
    } catch (err) {
      return { ok: false, blocked: true, reason: REASON.REMOTE_DICTIONARY, provider };
    }
    if (url.username || url.password) {
      return { ok: false, blocked: true, reason: REASON.CREDENTIALS, provider };
    }
    const local = url.protocol === 'file:' || url.hostname === 'localhost' || url.hostname === '127.0.0.1';
    if (!local) {
      return { ok: false, blocked: true, reason: REASON.REMOTE_DICTIONARY, provider };
    }
  }
  if (cfg.endpoint) {
    const endpoint = String(cfg.endpoint);
    if (!endpoint.startsWith('https://') && !endpoint.startsWith('http://127.0.0.1')) {
      return { ok: false, blocked: true, reason: REASON.INSECURE_ENDPOINT, provider };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, provider };
}

function evaluateSessionPreferences(prefs) {
  const p = prefs || {};
  const result = evaluateSpellcheck({ provider: p.spellcheckProvider, dictionaryUrl: p.dictionaryUrl });
  if (result.blocked) return { ...result, field: 'spellcheckProvider' };
  if (p.spellcheckLanguages && Array.isArray(p.spellcheckLanguages)) {
    const list = p.spellcheckLanguages;
    if (list.length > 32) {
      return { ok: false, blocked: true, reason: REASON.UNKNOWN_PROVIDER, provider: result.provider, field: 'spellcheckLanguages' };
    }
    for (const language of list) {
      if (typeof language !== 'string' || language.length > 32) {
        return { ok: false, blocked: true, reason: REASON.UNKNOWN_PROVIDER, provider: result.provider, field: 'spellcheckLanguages' };
      }
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, provider: result.provider };
}

function auditSpellcheckBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateSessionPreferences(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ provider: result.provider, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no spellcheck privacy risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.provider || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateSpellcheck,
  evaluateSessionPreferences,
  auditSpellcheckBatch,
  describeFindings,
};
