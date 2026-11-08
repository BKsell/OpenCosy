'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hddfirm', prefix: 'HDDFIRM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHddfirmGuard: guard.evaluate,
  summarizeHddfirmGuard: guard.summarize,
  describeHddfirmGuard: guard.describe,
};
