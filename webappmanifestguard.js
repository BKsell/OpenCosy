'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'webappmanifest', prefix: 'WEBAPPMAN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWebappmanifestGuard: guard.evaluate,
  summarizeWebappmanifestGuard: guard.summarize,
  describeWebappmanifestGuard: guard.describe,
};
