'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'CACHECONT', label: '私有缓存控制' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCachecontrolprivaterequire: guard.evaluate,
  summarizeCachecontrolprivaterequire: guard.summarize,
  describeCachecontrolprivaterequire: guard.describe,
};
