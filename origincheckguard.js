'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'origincheck', prefix: 'ORIGINCHE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOrigincheckGuard: guard.evaluate,
  summarizeOrigincheckGuard: guard.summarize,
  describeOrigincheckGuard: guard.describe,
};
