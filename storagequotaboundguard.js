'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'STORAGEQU', label: '存储配额上限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateStoragequotabound: guard.evaluate,
  summarizeStoragequotabound: guard.summarize,
  describeStoragequotabound: guard.describe,
};
