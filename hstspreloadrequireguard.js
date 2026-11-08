'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'HSTSPRELO', label: 'HSTS 预加载' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHstspreloadrequire: guard.evaluate,
  summarizeHstspreloadrequire: guard.summarize,
  describeHstspreloadrequire: guard.describe,
};
