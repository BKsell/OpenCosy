'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'EARLYHINT', label: 'Early Hints 白名单' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEarlyhintallowlist: guard.evaluate,
  summarizeEarlyhintallowlist: guard.summarize,
  describeEarlyhintallowlist: guard.describe,
};
