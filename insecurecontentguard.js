'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'insecurecontent', prefix: 'INSECUREC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateInsecurecontentGuard: guard.evaluate,
  summarizeInsecurecontentGuard: guard.summarize,
  describeInsecurecontentGuard: guard.describe,
};
