'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'smuggling', prefix: 'SMUGGLING' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSmugglingGuard: guard.evaluate,
  summarizeSmugglingGuard: guard.summarize,
  describeSmugglingGuard: guard.describe,
};
