'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'smap', prefix: 'SMAP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSmapGuard: guard.evaluate,
  summarizeSmapGuard: guard.summarize,
  describeSmapGuard: guard.describe,
};
