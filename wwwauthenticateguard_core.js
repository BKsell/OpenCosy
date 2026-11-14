const { REASON, SCHEME, QUOTED, MAX_LENGTH, MAX_CHALLENGES, hasControlChar, parseChallenge } = require('./authchallengeparse_core');
'use strict';
const { describeReasonTable } = require('./reasontext');

const { headerKey } = require('./headerutil_core');

function inspectAuthenticate(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return { present: false, key: '', challenges: [], reason: REASON.MISSING };
  const raw = headers[key];
  const list = Array.isArray(raw) ? raw : [raw];
  if (list.length > MAX_CHALLENGES) {
    return { present: true, key, challenges: [], reason: REASON.TOO_MANY };
  }
  const challenges = list.map(parseChallenge);
  const bad = challenges.find((item) => item.reason !== REASON.OK);
  return {
    present: true,
    key,
    challenges,
    reason: bad ? bad.reason : REASON.OK,
  };
}

function applyWwwAuthenticateGuard(headers, name) {
  const result = inspectAuthenticate(headers, name);
  if (!result.present) return { changed: false, reason: REASON.MISSING, challenges: 0 };
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, challenges: result.challenges.length };
  }
  delete headers[result.key];
  return { changed: true, reason: result.reason, challenges: 0 };
}

const describeReason = describeReasonTable({
    [REASON.MISSING]: '未声明认证挑战',
    [REASON.MALFORMED]: '认证挑战参数无法解析，已移除',
    [REASON.BAD_SCHEME]: '认证方案名非法，已移除',
    [REASON.CONTROL_CHAR]: '认证挑战含控制字符，已移除',
    [REASON.OVERLONG]: '认证挑战超长，已移除',
    [REASON.BAD_REALM]: 'realm 引号不完整，已移除',
    [REASON.TOO_MANY]: '认证挑战数量超限，已移除',
  }, '认证挑战通过校验');

module.exports = {
  REASON,
  MAX_LENGTH,
  MAX_CHALLENGES,
  parseChallenge,
  inspectAuthenticate,
  applyWwwAuthenticateGuard,
  describeReason,
};
