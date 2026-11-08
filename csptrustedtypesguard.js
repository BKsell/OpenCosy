'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'csptrustedtypes', prefix: 'CSPTRUSTE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCsptrustedtypesGuard: guard.evaluate,
  summarizeCsptrustedtypesGuard: guard.summarize,
  describeCsptrustedtypesGuard: guard.describe,
};
