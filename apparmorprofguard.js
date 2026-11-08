'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'apparmorprof', prefix: 'APPARMORP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateApparmorprofGuard: guard.evaluate,
  summarizeApparmorprofGuard: guard.summarize,
  describeApparmorprofGuard: guard.describe,
};
