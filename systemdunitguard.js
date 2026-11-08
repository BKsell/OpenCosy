'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'systemdunit', prefix: 'SYSTEMDUN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSystemdunitGuard: guard.evaluate,
  summarizeSystemdunitGuard: guard.summarize,
  describeSystemdunitGuard: guard.describe,
};
