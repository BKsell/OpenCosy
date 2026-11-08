'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'partitionpersist', prefix: 'PARTITION' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePartitionpersistGuard: guard.evaluate,
  summarizePartitionpersistGuard: guard.summarize,
  describePartitionpersistGuard: guard.describe,
};
