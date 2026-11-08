'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'fileurl', prefix: 'FILEURL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFileurlGuard: guard.evaluate,
  summarizeFileurlGuard: guard.summarize,
  describeFileurlGuard: guard.describe,
};
