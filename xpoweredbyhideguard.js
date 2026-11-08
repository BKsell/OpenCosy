'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'XPOWEREDB', label: 'X-Powered-By 隐藏' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXpoweredbyhide: guard.evaluate,
  summarizeXpoweredbyhide: guard.summarize,
  describeXpoweredbyhide: guard.describe,
};
