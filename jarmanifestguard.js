'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'jarmanifest', prefix: 'JARMANIFE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJarmanifestGuard: guard.evaluate,
  summarizeJarmanifestGuard: guard.summarize,
  describeJarmanifestGuard: guard.describe,
};
