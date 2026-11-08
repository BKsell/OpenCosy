'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'modprobe', prefix: 'MODPROBE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateModprobeGuard: guard.evaluate,
  summarizeModprobeGuard: guard.summarize,
  describeModprobeGuard: guard.describe,
};
