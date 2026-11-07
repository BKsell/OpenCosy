'use strict';

const REASON = {
  SPELL_LANG_EMPTY: 'spell-lang-empty',
  SPELL_LANG_INVALID: 'spell-lang-invalid',
  SPELL_LANG_LIMIT: 'spell-lang-limit',
  SPELL_DICT_NOT_HTTPS: 'spell-dict-not-https',
  SPELL_REMOTE_RISK: 'spell-remote-risk',
};

const LIMITS = {
  MAX_LANGUAGES: 6,
};

function pick(source, path) {
  let current = source;
  for (const part of path.split('.')) {
    if (!current || typeof current !== 'object') return undefined;
    current = current[part];
  }
  return current;
}

function text(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function evaluateSpellcheckLanguageGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  const spell_lang_emptyList = Array.isArray(pick(data, 'languages')) ? pick(data, 'languages') : [];
  if (spell_lang_emptyList.length === 0) {
    add(REASON.SPELL_LANG_EMPTY, '拼写检查未启用任何语言', false);
  }

  const spell_lang_invalidList = Array.isArray(pick(data, 'languages')) ? pick(data, 'languages') : [];
  const spell_lang_invalidHit = spell_lang_invalidList.some((item) => new RegExp('^[^a-zA-Z]|[^A-Za-z0-9-]').test(String((item && typeof item === 'object' ? item : item) || '')));
  if (spell_lang_invalidHit) {
    add(REASON.SPELL_LANG_INVALID, '语言标签不符合 BCP 47', true);
  }

  const spell_lang_limitList = Array.isArray(pick(data, 'languages')) ? pick(data, 'languages') : [];
  if (spell_lang_limitList.length > 6) {
    add(REASON.SPELL_LANG_LIMIT, '拼写语言数量超出上限', false);
  }

  if (new RegExp('^(?!https://).').test(text(pick(data, 'dictionaryUrl')))) {
    add(REASON.SPELL_DICT_NOT_HTTPS, '远程词典地址不是 HTTPS', true);
  }

  if (pick(data, 'remoteDictionary') === true) {
    add(REASON.SPELL_REMOTE_RISK, '远程词典会向第三方泄露输入内容', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeSpellcheckLanguageGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateSpellcheckLanguageGuard, describeSpellcheckLanguageGuard };
