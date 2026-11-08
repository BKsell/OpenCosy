'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'weakref', prefix: 'WEAKREF' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWeakrefGuard: guard.evaluate,
  summarizeWeakrefGuard: guard.summarize,
  describeWeakrefGuard: guard.describe,
};
