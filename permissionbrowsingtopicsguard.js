'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '浏览主题权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionbrowsingtopics: guard.evaluate,
  summarizePermissionbrowsingtopics: guard.summarize,
  describePermissionbrowsingtopics: guard.describe,
};
