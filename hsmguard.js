'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hsm', prefix: 'HSM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHsmGuard: guard.evaluate,
  summarizeHsmGuard: guard.summarize,
  describeHsmGuard: guard.describe,
};
