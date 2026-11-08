'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'CRITICALC', label: 'Critical-CH 限制' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCriticalchforbid: guard.evaluate,
  summarizeCriticalchforbid: guard.summarize,
  describeCriticalchforbid: guard.describe,
};
