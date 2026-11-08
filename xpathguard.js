'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'xpath', prefix: 'XPATH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXpathGuard: guard.evaluate,
  summarizeXpathGuard: guard.summarize,
  describeXpathGuard: guard.describe,
};
