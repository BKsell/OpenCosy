'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'LASTMODIF', label: 'Last-Modified 精度' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateLastmodifiedprecision: guard.evaluate,
  summarizeLastmodifiedprecision: guard.summarize,
  describeLastmodifiedprecision: guard.describe,
};
