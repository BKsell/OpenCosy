'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'CACHECONT', label: '不可变缓存' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCachecontrolimmutable: guard.evaluate,
  summarizeCachecontrolimmutable: guard.summarize,
  describeCachecontrolimmutable: guard.describe,
};
