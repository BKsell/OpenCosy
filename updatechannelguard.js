'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'updatechannel', prefix: 'UPDATECHA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUpdatechannelGuard: guard.evaluate,
  summarizeUpdatechannelGuard: guard.summarize,
  describeUpdatechannelGuard: guard.describe,
};
