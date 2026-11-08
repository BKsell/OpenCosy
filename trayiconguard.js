'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'trayicon', prefix: 'TRAYICON' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTrayiconGuard: guard.evaluate,
  summarizeTrayiconGuard: guard.summarize,
  describeTrayiconGuard: guard.describe,
};
