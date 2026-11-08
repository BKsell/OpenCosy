'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tabpreview', prefix: 'TABPREVIE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTabpreviewGuard: guard.evaluate,
  summarizeTabpreviewGuard: guard.summarize,
  describeTabpreviewGuard: guard.describe,
};
