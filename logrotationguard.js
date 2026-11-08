'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'logrotation', prefix: 'LOGROTATI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateLogrotationGuard: guard.evaluate,
  summarizeLogrotationGuard: guard.summarize,
  describeLogrotationGuard: guard.describe,
};
