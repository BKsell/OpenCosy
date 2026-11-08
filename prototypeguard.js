'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'prototype', prefix: 'PROTOTYPE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePrototypeGuard: guard.evaluate,
  summarizePrototypeGuard: guard.summarize,
  describePrototypeGuard: guard.describe,
};
