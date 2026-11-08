'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'redirectorigin', prefix: 'REDIRECTO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRedirectoriginGuard: guard.evaluate,
  summarizeRedirectoriginGuard: guard.summarize,
  describeRedirectoriginGuard: guard.describe,
};
