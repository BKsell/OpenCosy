'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'spectremitigation', prefix: 'SPECTREMI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSpectremitigationGuard: guard.evaluate,
  summarizeSpectremitigationGuard: guard.summarize,
  describeSpectremitigationGuard: guard.describe,
};
