'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'midi', prefix: 'MIDI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMidiGuard: guard.evaluate,
  summarizeMidiGuard: guard.summarize,
  describeMidiGuard: guard.describe,
};
