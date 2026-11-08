'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'spellcheck', prefix: 'SPELLCHEC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSpellcheckGuard: guard.evaluate,
  summarizeSpellcheckGuard: guard.summarize,
  describeSpellcheckGuard: guard.describe,
};
