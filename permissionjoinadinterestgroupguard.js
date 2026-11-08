'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '广告兴趣组权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionjoinadinterestgroup: guard.evaluate,
  summarizePermissionjoinadinterestgroup: guard.summarize,
  describePermissionjoinadinterestgroup: guard.describe,
};
