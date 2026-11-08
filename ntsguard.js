'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'nts', prefix: 'NTS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNtsGuard: guard.evaluate,
  summarizeNtsGuard: guard.summarize,
  describeNtsGuard: guard.describe,
};
