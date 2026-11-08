'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'protobuf', prefix: 'PROTOBUF' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateProtobufGuard: guard.evaluate,
  summarizeProtobufGuard: guard.summarize,
  describeProtobufGuard: guard.describe,
};
