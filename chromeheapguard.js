'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'chromeheap', prefix: 'CHROMEHEA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateChromeheapGuard: guard.evaluate,
  summarizeChromeheapGuard: guard.summarize,
  describeChromeheapGuard: guard.describe,
};
