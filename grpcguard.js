'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'grpc', prefix: 'GRPC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGrpcGuard: guard.evaluate,
  summarizeGrpcGuard: guard.summarize,
  describeGrpcGuard: guard.describe,
};
