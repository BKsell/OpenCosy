'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sshkeys', prefix: 'SSHKEYS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSshkeysGuard: guard.evaluate,
  summarizeSshkeysGuard: guard.summarize,
  describeSshkeysGuard: guard.describe,
};
