'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'DNSREBIND', label: 'DNS 重绑定' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDnsrebinding: guard.evaluate,
  summarizeDnsrebinding: guard.summarize,
  describeDnsrebinding: guard.describe,
};
