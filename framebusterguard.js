'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'framebuster', prefix: 'FRAMEBUST' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFramebusterGuard: guard.evaluate,
  summarizeFramebusterGuard: guard.summarize,
  describeFramebusterGuard: guard.describe,
};
