'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'remotecontent', prefix: 'REMOTECON' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRemotecontentGuard: guard.evaluate,
  summarizeRemotecontentGuard: guard.summarize,
  describeRemotecontentGuard: guard.describe,
};
