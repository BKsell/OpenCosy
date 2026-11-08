'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'CROSSORIG', label: '跨域计时白名单' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCrossorigintiming: guard.evaluate,
  summarizeCrossorigintiming: guard.summarize,
  describeCrossorigintiming: guard.describe,
};
