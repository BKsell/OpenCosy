'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'deserialize', prefix: 'DESERIALI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDeserializeGuard: guard.evaluate,
  summarizeDeserializeGuard: guard.summarize,
  describeDeserializeGuard: guard.describe,
};
