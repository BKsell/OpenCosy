'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'remoteenabled', prefix: 'REMOTEENA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRemoteenabledGuard: guard.evaluate,
  summarizeRemoteenabledGuard: guard.summarize,
  describeRemoteenabledGuard: guard.describe,
};
