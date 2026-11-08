'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'arpspoof', prefix: 'ARPSPOOF' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateArpspoofGuard: guard.evaluate,
  summarizeArpspoofGuard: guard.summarize,
  describeArpspoofGuard: guard.describe,
};
