'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: 'MIDI 权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionmidirequire: guard.evaluate,
  summarizePermissionmidirequire: guard.summarize,
  describePermissionmidirequire: guard.describe,
};
