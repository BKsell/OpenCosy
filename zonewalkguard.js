'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'zonewalk', prefix: 'ZONEWALK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateZonewalkGuard: guard.evaluate,
  summarizeZonewalkGuard: guard.summarize,
  describeZonewalkGuard: guard.describe,
};
