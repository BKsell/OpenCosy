'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'agentattach', prefix: 'AGENTATTA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAgentattachGuard: guard.evaluate,
  summarizeAgentattachGuard: guard.summarize,
  describeAgentattachGuard: guard.describe,
};
