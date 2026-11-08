'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'webglcontext', prefix: 'WEBGLCONT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWebglcontextGuard: guard.evaluate,
  summarizeWebglcontextGuard: guard.summarize,
  describeWebglcontextGuard: guard.describe,
};
