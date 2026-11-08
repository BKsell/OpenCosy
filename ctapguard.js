'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ctap', prefix: 'CTAP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCtapGuard: guard.evaluate,
  summarizeCtapGuard: guard.summarize,
  describeCtapGuard: guard.describe,
};
