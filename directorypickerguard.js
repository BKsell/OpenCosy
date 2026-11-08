'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'directorypicker', prefix: 'DIRECTORY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDirectorypickerGuard: guard.evaluate,
  summarizeDirectorypickerGuard: guard.summarize,
  describeDirectorypickerGuard: guard.describe,
};
