'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'resume', prefix: 'RESUME' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateResumeGuard: guard.evaluate,
  summarizeResumeGuard: guard.summarize,
  describeResumeGuard: guard.describe,
};
