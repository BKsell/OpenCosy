'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'openerpolicy', prefix: 'OPENERPOL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOpenerpolicyGuard: guard.evaluate,
  summarizeOpenerpolicyGuard: guard.summarize,
  describeOpenerpolicyGuard: guard.describe,
};
