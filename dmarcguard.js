'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dmarc', prefix: 'DMARC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDmarcGuard: guard.evaluate,
  summarizeDmarcGuard: guard.summarize,
  describeDmarcGuard: guard.describe,
};
