'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'rfidclone', prefix: 'RFIDCLONE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRfidcloneGuard: guard.evaluate,
  summarizeRfidcloneGuard: guard.summarize,
  describeRfidcloneGuard: guard.describe,
};
