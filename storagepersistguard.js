'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'storagepersist', prefix: 'STORAGEPE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateStoragepersistGuard: guard.evaluate,
  summarizeStoragepersistGuard: guard.summarize,
  describeStoragepersistGuard: guard.describe,
};
