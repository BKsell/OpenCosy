'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'devtoolsdisabled', prefix: 'DEVTOOLSD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDevtoolsdisabledGuard: guard.evaluate,
  summarizeDevtoolsdisabledGuard: guard.summarize,
  describeDevtoolsdisabledGuard: guard.describe,
};
