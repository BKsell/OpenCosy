'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'swscope', prefix: 'SWSCOPE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSwscopeGuard: guard.evaluate,
  summarizeSwscopeGuard: guard.summarize,
  describeSwscopeGuard: guard.describe,
};
