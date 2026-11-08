'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'javaagent', prefix: 'JAVAAGENT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJavaagentGuard: guard.evaluate,
  summarizeJavaagentGuard: guard.summarize,
  describeJavaagentGuard: guard.describe,
};
