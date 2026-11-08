'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'idbpersist', prefix: 'IDBPERSIS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIdbpersistGuard: guard.evaluate,
  summarizeIdbpersistGuard: guard.summarize,
  describeIdbpersistGuard: guard.describe,
};
