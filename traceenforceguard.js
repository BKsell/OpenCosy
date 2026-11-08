'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'TRACEENFO', label: 'TRACE 方法禁用' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTraceenforce: guard.evaluate,
  summarizeTraceenforce: guard.summarize,
  describeTraceenforce: guard.describe,
};
