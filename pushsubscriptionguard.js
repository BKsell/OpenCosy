'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pushsubscription', prefix: 'PUSHSUBSC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePushsubscriptionGuard: guard.evaluate,
  summarizePushsubscriptionGuard: guard.summarize,
  describePushsubscriptionGuard: guard.describe,
};
