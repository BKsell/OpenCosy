'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sni', prefix: 'SNI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSniGuard: guard.evaluate,
  summarizeSniGuard: guard.summarize,
  describeSniGuard: guard.describe,
};
