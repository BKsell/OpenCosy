'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'multipartboundary', prefix: 'MULTIPART' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMultipartboundaryGuard: guard.evaluate,
  summarizeMultipartboundaryGuard: guard.summarize,
  describeMultipartboundaryGuard: guard.describe,
};
