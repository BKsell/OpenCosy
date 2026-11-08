'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'yamlbomb', prefix: 'YAMLBOMB' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateYamlbombGuard: guard.evaluate,
  summarizeYamlbombGuard: guard.summarize,
  describeYamlbombGuard: guard.describe,
};
