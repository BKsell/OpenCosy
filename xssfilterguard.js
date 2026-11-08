'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'xssfilter', prefix: 'XSSFILTER' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXssfilterGuard: guard.evaluate,
  summarizeXssfilterGuard: guard.summarize,
  describeXssfilterGuard: guard.describe,
};
