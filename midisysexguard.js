'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'midisysex', prefix: 'MIDISYSEX' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMidisysexGuard: guard.evaluate,
  summarizeMidisysexGuard: guard.summarize,
  describeMidisysexGuard: guard.describe,
};
