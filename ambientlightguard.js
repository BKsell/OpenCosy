'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ambientlight', prefix: 'AMBIENTLI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAmbientlightGuard: guard.evaluate,
  summarizeAmbientlightGuard: guard.summarize,
  describeAmbientlightGuard: guard.describe,
};
