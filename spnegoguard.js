'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'spnego', prefix: 'SPNEGO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSpnegoGuard: guard.evaluate,
  summarizeSpnegoGuard: guard.summarize,
  describeSpnegoGuard: guard.describe,
};
