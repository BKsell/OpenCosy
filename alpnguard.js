'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'alpn', prefix: 'ALPN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAlpnGuard: guard.evaluate,
  summarizeAlpnGuard: guard.summarize,
  describeAlpnGuard: guard.describe,
};
