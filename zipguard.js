'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'zip', prefix: 'ZIP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateZipGuard: guard.evaluate,
  summarizeZipGuard: guard.summarize,
  describeZipGuard: guard.describe,
};
