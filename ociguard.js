'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'oci', prefix: 'OCI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOciGuard: guard.evaluate,
  summarizeOciGuard: guard.summarize,
  describeOciGuard: guard.describe,
};
