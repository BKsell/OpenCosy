'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'DOWNLOADM', label: '下载类型白名单' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDownloadmimetype: guard.evaluate,
  summarizeDownloadmimetype: guard.summarize,
  describeDownloadmimetype: guard.describe,
};
