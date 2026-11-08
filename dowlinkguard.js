'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dowlink', prefix: 'DOWLINK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDowlinkGuard: guard.evaluate,
  summarizeDowlinkGuard: guard.summarize,
  describeDowlinkGuard: guard.describe,
};
