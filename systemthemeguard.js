'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'systemtheme', prefix: 'SYSTEMTHE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSystemthemeGuard: guard.evaluate,
  summarizeSystemthemeGuard: guard.summarize,
  describeSystemthemeGuard: guard.describe,
};
