'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'jtagdebug', prefix: 'JTAGDEBUG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJtagdebugGuard: guard.evaluate,
  summarizeJtagdebugGuard: guard.summarize,
  describeJtagdebugGuard: guard.describe,
};
