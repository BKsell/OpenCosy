'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'soap', prefix: 'SOAP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSoapGuard: guard.evaluate,
  summarizeSoapGuard: guard.summarize,
  describeSoapGuard: guard.describe,
};
