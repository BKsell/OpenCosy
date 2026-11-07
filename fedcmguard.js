'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'fedcm-empty',
  INSECURE: 'fedcm-insecure',
  IDP_NOT_ALLOWED: 'fedcm-idp-not-allowed',
  MISSING_METADATA: 'fedcm-missing-metadata',
  AUTO_REAUTH: 'fedcm-auto-reauth',
  OVERSIZED_CONFIG: 'fedcm-oversized-config',
};

const MAX_CONFIG = 64;

function normalizeOrigin(value) {
  const text = typeof value === 'string' ? value.trim() : '';
  if (text === '') return '';
  try {
    return new URL(text).origin.toLowerCase();
  } catch (err) {
    return '';
  }
}

function evaluateFedcm(config, options) {
  const opts = options || {};
  const item = config || {};
  const origin = normalizeOrigin(item.origin);
  if (origin === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  if (!origin.startsWith('https://')) {
    return { ok: false, blocked: true, reason: REASON.INSECURE, origin };
  }
  const providers = Array.isArray(item.providers) ? item.providers : [];
  if (providers.length === 0) return { ok: false, blocked: true, reason: REASON.EMPTY, origin };
  if (providers.length > MAX_CONFIG) {
    return { ok: false, blocked: true, reason: REASON.OVERSIZED_CONFIG, count: providers.length };
  }
  const allow = Array.isArray(opts.allowIdp) ? opts.allowIdp.map(normalizeOrigin) : [];
  for (const provider of providers) {
    const idp = normalizeOrigin(provider && provider.configURL ? stripConfigPath(provider.configURL) : '');
    if (idp === '' || !idp.startsWith('https://')) {
      return { ok: false, blocked: true, reason: REASON.MISSING_METADATA, provider: String(provider && provider.configURL || '').slice(0, 64) };
    }
    if (allow.length > 0 && !allow.includes(idp)) {
      return { ok: false, blocked: true, reason: REASON.IDP_NOT_ALLOWED, idp };
    }
    if (provider && provider.clientMetadata && typeof provider.clientMetadata === 'object') {
      const metadataOrigin = normalizeOrigin(provider.clientMetadata.privacy_policy_url);
      if (metadataOrigin === '') {
        return { ok: false, blocked: true, reason: REASON.MISSING_METADATA, idp };
      }
    }
  }
  if (opts.allowAutoReauth !== true && item.mediation === 'silent') {
    return { ok: false, blocked: true, reason: REASON.AUTO_REAUTH, origin };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin, providers: providers.length };
}

function stripConfigPath(url) {
  const text = typeof url === 'string' ? url.trim() : '';
  const idx = text.indexOf('/.well-known/');
  if (idx === -1) return text;
  return text.slice(0, idx);
}

module.exports = {
  REASON,
  MAX_CONFIG,
  normalizeOrigin,
  evaluateFedcm,
};
