'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'getterleak', prefix: 'GETTERLEA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGetterleakGuard: guard.evaluate,
  summarizeGetterleakGuard: guard.summarize,
  describeGetterleakGuard: guard.describe,
};
