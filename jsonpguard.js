'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'jsonp', prefix: 'JSONP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJsonpGuard: guard.evaluate,
  summarizeJsonpGuard: guard.summarize,
  describeJsonpGuard: guard.describe,
};
