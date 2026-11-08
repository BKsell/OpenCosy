'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'ROBOTSNOI', label: 'robots noindex' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRobotsnoindex: guard.evaluate,
  summarizeRobotsnoindex: guard.summarize,
  describeRobotsnoindex: guard.describe,
};
