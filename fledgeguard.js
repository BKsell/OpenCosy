'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'fledge', prefix: 'FLEDGE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFledgeGuard: guard.evaluate,
  summarizeFledgeGuard: guard.summarize,
  describeFledgeGuard: guard.describe,
};
