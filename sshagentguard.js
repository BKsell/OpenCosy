'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sshagent', prefix: 'SSHAGENT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSshagentGuard: guard.evaluate,
  summarizeSshagentGuard: guard.summarize,
  describeSshagentGuard: guard.describe,
};
