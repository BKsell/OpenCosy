'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'workspace', prefix: 'WORKSPACE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWorkspaceGuard: guard.evaluate,
  summarizeWorkspaceGuard: guard.summarize,
  describeWorkspaceGuard: guard.describe,
};
