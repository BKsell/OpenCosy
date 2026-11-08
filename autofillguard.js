'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'autofill', prefix: 'AUTOFILL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAutofillGuard: guard.evaluate,
  summarizeAutofillGuard: guard.summarize,
  describeAutofillGuard: guard.describe,
};
