'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'samlsso', prefix: 'SAMLSSO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSamlssoGuard: guard.evaluate,
  summarizeSamlssoGuard: guard.summarize,
  describeSamlssoGuard: guard.describe,
};
