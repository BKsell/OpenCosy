'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'marshaling', prefix: 'MARSHALIN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMarshalingGuard: guard.evaluate,
  summarizeMarshalingGuard: guard.summarize,
  describeMarshalingGuard: guard.describe,
};
