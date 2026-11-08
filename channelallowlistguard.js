'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'channelallowlist', prefix: 'CHANNELAL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateChannelallowlistGuard: guard.evaluate,
  summarizeChannelallowlistGuard: guard.summarize,
  describeChannelallowlistGuard: guard.describe,
};
