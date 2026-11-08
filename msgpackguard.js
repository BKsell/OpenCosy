'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'msgpack', prefix: 'MSGPACK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMsgpackGuard: guard.evaluate,
  summarizeMsgpackGuard: guard.summarize,
  describeMsgpackGuard: guard.describe,
};
