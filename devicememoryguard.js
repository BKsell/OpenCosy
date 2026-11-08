'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'devicememory', prefix: 'DEVICEMEM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDevicememoryGuard: guard.evaluate,
  summarizeDevicememoryGuard: guard.summarize,
  describeDevicememoryGuard: guard.describe,
};
