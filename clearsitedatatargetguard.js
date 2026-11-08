'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'CLEARSITE', label: 'Clear-Site-Data 目标' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateClearsitedatatarget: guard.evaluate,
  summarizeClearsitedatatarget: guard.summarize,
  describeClearsitedatatarget: guard.describe,
};
