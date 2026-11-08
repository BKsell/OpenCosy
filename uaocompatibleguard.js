'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'UAOCOMPAT', label: 'UA 兼容模式' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUaocompatible: guard.evaluate,
  summarizeUaocompatible: guard.summarize,
  describeUaocompatible: guard.describe,
};
