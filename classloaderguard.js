'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'classloader', prefix: 'CLASSLOAD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateClassloaderGuard: guard.evaluate,
  summarizeClassloaderGuard: guard.summarize,
  describeClassloaderGuard: guard.describe,
};
