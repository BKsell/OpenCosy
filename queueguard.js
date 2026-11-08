'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'queue', prefix: 'QUEUE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateQueueGuard: guard.evaluate,
  summarizeQueueGuard: guard.summarize,
  describeQueueGuard: guard.describe,
};
