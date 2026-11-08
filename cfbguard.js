'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cfb', prefix: 'CFB' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCfbGuard: guard.evaluate,
  summarizeCfbGuard: guard.summarize,
  describeCfbGuard: guard.describe,
};
