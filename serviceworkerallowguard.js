'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'serviceworkerallow', prefix: 'SERVICEWO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateServiceworkerallowGuard: guard.evaluate,
  summarizeServiceworkerallowGuard: guard.summarize,
  describeServiceworkerallowGuard: guard.describe,
};
