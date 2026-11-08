'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'broadcastchannel', prefix: 'BROADCAST' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBroadcastchannelGuard: guard.evaluate,
  summarizeBroadcastchannelGuard: guard.summarize,
  describeBroadcastchannelGuard: guard.describe,
};
