'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'contextisolation', prefix: 'CONTEXTIS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateContextisolationGuard: guard.evaluate,
  summarizeContextisolationGuard: guard.summarize,
  describeContextisolationGuard: guard.describe,
};
