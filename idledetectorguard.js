'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'idledetector', prefix: 'IDLEDETEC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIdledetectorGuard: guard.evaluate,
  summarizeIdledetectorGuard: guard.summarize,
  describeIdledetectorGuard: guard.describe,
};
