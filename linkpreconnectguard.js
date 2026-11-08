'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'linkpreconnect', prefix: 'LINKPRECO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateLinkpreconnectGuard: guard.evaluate,
  summarizeLinkpreconnectGuard: guard.summarize,
  describeLinkpreconnectGuard: guard.describe,
};
