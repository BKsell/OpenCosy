'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'messagechannel', prefix: 'MESSAGECH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMessagechannelGuard: guard.evaluate,
  summarizeMessagechannelGuard: guard.summarize,
  describeMessagechannelGuard: guard.describe,
};
