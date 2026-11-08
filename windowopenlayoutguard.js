'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'windowopenlayout', prefix: 'WINDOWOPE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWindowopenlayoutGuard: guard.evaluate,
  summarizeWindowopenlayoutGuard: guard.summarize,
  describeWindowopenlayoutGuard: guard.describe,
};
