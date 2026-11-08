'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: 'NFC 权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionnfc: guard.evaluate,
  summarizePermissionnfc: guard.summarize,
  describePermissionnfc: guard.describe,
};
