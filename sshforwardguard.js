'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sshforward', prefix: 'SSHFORWAR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSshforwardGuard: guard.evaluate,
  summarizeSshforwardGuard: guard.summarize,
  describeSshforwardGuard: guard.describe,
};
