'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'openredirect', prefix: 'OPENREDIR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOpenredirectGuard: guard.evaluate,
  summarizeOpenredirectGuard: guard.summarize,
  describeOpenredirectGuard: guard.describe,
};
