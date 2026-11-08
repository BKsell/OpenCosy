'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'websocket', prefix: 'WEBSOCKET' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWebsocketGuard: guard.evaluate,
  summarizeWebsocketGuard: guard.summarize,
  describeWebsocketGuard: guard.describe,
};
