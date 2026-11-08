'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'extension', prefix: 'EXTENSION' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateExtensionGuard: guard.evaluate,
  summarizeExtensionGuard: guard.summarize,
  describeExtensionGuard: guard.describe,
};
