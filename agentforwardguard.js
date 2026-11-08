'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'agentforward', prefix: 'AGENTFORW' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAgentforwardGuard: guard.evaluate,
  summarizeAgentforwardGuard: guard.summarize,
  describeAgentforwardGuard: guard.describe,
};
