'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'windowclose', prefix: 'WINDOWCLO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWindowcloseGuard: guard.evaluate,
  summarizeWindowcloseGuard: guard.summarize,
  describeWindowcloseGuard: guard.describe,
};
