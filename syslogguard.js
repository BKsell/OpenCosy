'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'syslog', prefix: 'SYSLOG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSyslogGuard: guard.evaluate,
  summarizeSyslogGuard: guard.summarize,
  describeSyslogGuard: guard.describe,
};
