'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'defaultbrowser', prefix: 'DEFAULTBR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDefaultbrowserGuard: guard.evaluate,
  summarizeDefaultbrowserGuard: guard.summarize,
  describeDefaultbrowserGuard: guard.describe,
};
