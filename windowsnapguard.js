'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'windowsnap', prefix: 'WINDOWSNA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWindowsnapGuard: guard.evaluate,
  summarizeWindowsnapGuard: guard.summarize,
  describeWindowsnapGuard: guard.describe,
};
