'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'domaincookie', prefix: 'DOMAINCOO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDomaincookieGuard: guard.evaluate,
  summarizeDomaincookieGuard: guard.summarize,
  describeDomaincookieGuard: guard.describe,
};
