'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'filepickeraccess', prefix: 'FILEPICKE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFilepickeraccessGuard: guard.evaluate,
  summarizeFilepickeraccessGuard: guard.summarize,
  describeFilepickeraccessGuard: guard.describe,
};
