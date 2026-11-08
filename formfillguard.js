'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'formfill', prefix: 'FORMFILL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFormfillGuard: guard.evaluate,
  summarizeFormfillGuard: guard.summarize,
  describeFormfillGuard: guard.describe,
};
