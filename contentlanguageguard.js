'use strict';
const { describeReasonTable } = require('./reasontext');

const { firstValue, headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  TOO_MANY: 'too-many-tags',
  WILDCARD: 'wildcard-tag',
};

const HEADER = 'content-language';
const MAX_TAGS = 5;
const MAX_TAG_LENGTH = 35;
const MAX_FIELD_LENGTH = 120;
const LANGUAGE_TAG = /^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/;

function parseLanguageTags(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, tags: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, tags: [] };
  if (text.length > MAX_FIELD_LENGTH) return { reason: REASON.OVERLONG, tags: [] };
  const tags = text.split(',').map((entry) => entry.trim()).filter((entry) => entry !== '');
  if (tags.length === 0) return { reason: REASON.MALFORMED, tags: [] };
  if (tags.length > MAX_TAGS) return { reason: REASON.TOO_MANY, tags };
  for (const tag of tags) {
    if (tag === '*') return { reason: REASON.WILDCARD, tags };
    if (tag.length > MAX_TAG_LENGTH) return { reason: REASON.OVERLONG, tags };
    if (!LANGUAGE_TAG.test(tag)) return { reason: REASON.MALFORMED, tags };
  }
  return { reason: REASON.OK, tags };
}

function inspectContentLanguage(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, tags: [] };
  const parsed = parseLanguageTags(value);
  if (parsed.reason !== REASON.OK) {
    return { changed: true, reason: parsed.reason, tags: parsed.tags };
  }
  return { changed: false, reason: REASON.OK, tags: parsed.tags };
}

function applyContentLanguageGuard(headers) {
  const result = inspectContentLanguage(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, HEADER);
  if (key) delete headers[key];
  return result;
}

const describeReason = describeReasonTable({
    [REASON.MALFORMED]: 'Content-Language 不是合法 BCP47 标签',
    [REASON.OVERLONG]: 'Content-Language 字段或标签超长',
    [REASON.TOO_MANY]: 'Content-Language 标签数量超限',
    [REASON.WILDCARD]: 'Content-Language 使用通配标签',
  }, 'Content-Language 通过校验');

module.exports = {
  REASON,
  HEADER,
  MAX_TAGS,
  MAX_TAG_LENGTH,
  MAX_FIELD_LENGTH,
  headerKey,
  firstValue,
  parseLanguageTags,
  inspectContentLanguage,
  applyContentLanguageGuard,
  describeReason,
};
