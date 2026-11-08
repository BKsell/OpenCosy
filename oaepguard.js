'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'oaep', prefix: 'OAEP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOaepGuard: guard.evaluate,
  summarizeOaepGuard: guard.summarize,
  describeOaepGuard: guard.describe,
};
