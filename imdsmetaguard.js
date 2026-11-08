'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'imdsmeta', prefix: 'IMDSMETA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateImdsmetaGuard: guard.evaluate,
  summarizeImdsmetaGuard: guard.summarize,
  describeImdsmetaGuard: guard.describe,
};
