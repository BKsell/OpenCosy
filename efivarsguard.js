'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'efivars', prefix: 'EFIVARS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEfivarsGuard: guard.evaluate,
  summarizeEfivarsGuard: guard.summarize,
  describeEfivarsGuard: guard.describe,
};
