'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'UPLOADMIM', label: '上传类型白名单' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUploadmimetype: guard.evaluate,
  summarizeUploadmimetype: guard.summarize,
  describeUploadmimetype: guard.describe,
};
