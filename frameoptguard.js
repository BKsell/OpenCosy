'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'frameopt', prefix: 'FRAMEOPT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFrameoptGuard: guard.evaluate,
  summarizeFrameoptGuard: guard.summarize,
  describeFrameoptGuard: guard.describe,
};
