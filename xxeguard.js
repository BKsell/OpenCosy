'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'xxe', prefix: 'XXE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXxeGuard: guard.evaluate,
  summarizeXxeGuard: guard.summarize,
  describeXxeGuard: guard.describe,
};
