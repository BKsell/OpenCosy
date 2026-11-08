'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'syslogd', prefix: 'SYSLOGD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSyslogdGuard: guard.evaluate,
  summarizeSyslogdGuard: guard.summarize,
  describeSyslogdGuard: guard.describe,
};
