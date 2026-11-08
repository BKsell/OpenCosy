'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sidepanel', prefix: 'SIDEPANEL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSidepanelGuard: guard.evaluate,
  summarizeSidepanelGuard: guard.summarize,
  describeSidepanelGuard: guard.describe,
};
