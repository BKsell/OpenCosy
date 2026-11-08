'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tabstrip', prefix: 'TABSTRIP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTabstripGuard: guard.evaluate,
  summarizeTabstripGuard: guard.summarize,
  describeTabstripGuard: guard.describe,
};
