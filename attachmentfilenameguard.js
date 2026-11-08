'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'ATTACHMEN', label: '附件文件名' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAttachmentfilename: guard.evaluate,
  summarizeAttachmentfilename: guard.summarize,
  describeAttachmentfilename: guard.describe,
};
