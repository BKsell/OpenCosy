'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'syslogforward', prefix: 'SYSLOGFOR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSyslogforwardGuard: guard.evaluate,
  summarizeSyslogforwardGuard: guard.summarize,
  describeSyslogforwardGuard: guard.describe,
};
