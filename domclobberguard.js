'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'domclobber', prefix: 'DOMCLOBBE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDomclobberGuard: guard.evaluate,
  summarizeDomclobberGuard: guard.summarize,
  describeDomclobberGuard: guard.describe,
};
