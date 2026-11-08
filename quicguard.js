'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'quic', prefix: 'QUIC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateQuicGuard: guard.evaluate,
  summarizeQuicGuard: guard.summarize,
  describeQuicGuard: guard.describe,
};
