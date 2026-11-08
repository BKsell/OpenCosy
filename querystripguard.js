'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'querystrip', prefix: 'QUERYSTRI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateQuerystripGuard: guard.evaluate,
  summarizeQuerystripGuard: guard.summarize,
  describeQuerystripGuard: guard.describe,
};
