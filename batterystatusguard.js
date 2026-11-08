'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'batterystatus', prefix: 'BATTERYST' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBatterystatusGuard: guard.evaluate,
  summarizeBatterystatusGuard: guard.summarize,
  describeBatterystatusGuard: guard.describe,
};
