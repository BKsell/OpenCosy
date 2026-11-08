'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'swddebug', prefix: 'SWDDEBUG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSwddebugGuard: guard.evaluate,
  summarizeSwddebugGuard: guard.summarize,
  describeSwddebugGuard: guard.describe,
};
