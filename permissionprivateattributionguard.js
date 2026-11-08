'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '私密归因权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionprivateattribution: guard.evaluate,
  summarizePermissionprivateattribution: guard.summarize,
  describePermissionprivateattribution: guard.describe,
};
