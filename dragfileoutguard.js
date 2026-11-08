'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dragfileout', prefix: 'DRAGFILEO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDragfileoutGuard: guard.evaluate,
  summarizeDragfileoutGuard: guard.summarize,
  describeDragfileoutGuard: guard.describe,
};
