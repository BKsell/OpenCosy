'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'NELPOLICY', label: 'NEL 策略' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNelpolicy: guard.evaluate,
  summarizeNelpolicy: guard.summarize,
  describeNelpolicy: guard.describe,
};
