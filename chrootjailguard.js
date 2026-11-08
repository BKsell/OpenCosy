'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'chrootjail', prefix: 'CHROOTJAI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateChrootjailGuard: guard.evaluate,
  summarizeChrootjailGuard: guard.summarize,
  describeChrootjailGuard: guard.describe,
};
