'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'CONTENTDI', label: 'Content-Disposition' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateContentdispositiontype: guard.evaluate,
  summarizeContentdispositiontype: guard.summarize,
  describeContentdispositiontype: guard.describe,
};
