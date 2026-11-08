'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'echconfig', prefix: 'ECHCONFIG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEchconfigGuard: guard.evaluate,
  summarizeEchconfigGuard: guard.summarize,
  describeEchconfigGuard: guard.describe,
};
