'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'envscrub', prefix: 'ENVSCRUB' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEnvscrubGuard: guard.evaluate,
  summarizeEnvscrubGuard: guard.summarize,
  describeEnvscrubGuard: guard.describe,
};
