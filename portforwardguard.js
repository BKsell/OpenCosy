'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'portforward', prefix: 'PORTFORWA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePortforwardGuard: guard.evaluate,
  summarizePortforwardGuard: guard.summarize,
  describePortforwardGuard: guard.describe,
};
