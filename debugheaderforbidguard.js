'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'DEBUGHEAD', label: '调试头禁用' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDebugheaderforbid: guard.evaluate,
  summarizeDebugheaderforbid: guard.summarize,
  describeDebugheaderforbid: guard.describe,
};
