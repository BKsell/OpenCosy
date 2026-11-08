'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'spellcheckpref', prefix: 'SPELLCHEC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSpellcheckprefGuard: guard.evaluate,
  summarizeSpellcheckprefGuard: guard.summarize,
  describeSpellcheckprefGuard: guard.describe,
};
