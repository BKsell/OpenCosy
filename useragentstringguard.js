'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'useragentstring', prefix: 'USERAGENT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUseragentstringGuard: guard.evaluate,
  summarizeUseragentstringGuard: guard.summarize,
  describeUseragentstringGuard: guard.describe,
};
