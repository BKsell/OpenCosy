'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'storagestale', prefix: 'STORAGEST' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateStoragestaleGuard: guard.evaluate,
  summarizeStoragestaleGuard: guard.summarize,
  describeStoragestaleGuard: guard.describe,
};
