'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'corsheaderlist', prefix: 'CORSHEADE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCorsheaderlistGuard: guard.evaluate,
  summarizeCorsheaderlistGuard: guard.summarize,
  describeCorsheaderlistGuard: guard.describe,
};
