'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'TLSMINIMU', label: '最低 TLS 版本' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTlsminimumversion: guard.evaluate,
  summarizeTlsminimumversion: guard.summarize,
  describeTlsminimumversion: guard.describe,
};
