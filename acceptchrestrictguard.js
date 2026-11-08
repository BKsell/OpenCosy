'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'ACCEPTCHR', label: 'Accept-CH 限制' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAcceptchrestrict: guard.evaluate,
  summarizeAcceptchrestrict: guard.summarize,
  describeAcceptchrestrict: guard.describe,
};
