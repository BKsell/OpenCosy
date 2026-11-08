'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'firmwaresig', prefix: 'FIRMWARES' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFirmwaresigGuard: guard.evaluate,
  summarizeFirmwaresigGuard: guard.summarize,
  describeFirmwaresigGuard: guard.describe,
};
