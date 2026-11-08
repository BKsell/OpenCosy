'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'yaml', prefix: 'YAML' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateYamlGuard: guard.evaluate,
  summarizeYamlGuard: guard.summarize,
  describeYamlGuard: guard.describe,
};
