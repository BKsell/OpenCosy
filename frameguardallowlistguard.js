'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'FRAMEGUAR', label: 'frame-ancestors 白名单' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFrameguardallowlist: guard.evaluate,
  summarizeFrameguardallowlist: guard.summarize,
  describeFrameguardallowlist: guard.describe,
};
