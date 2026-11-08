'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'basicauth', prefix: 'BASICAUTH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBasicauthGuard: guard.evaluate,
  summarizeBasicauthGuard: guard.summarize,
  describeBasicauthGuard: guard.describe,
};
