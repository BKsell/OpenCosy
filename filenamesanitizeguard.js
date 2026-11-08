'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'FILENAMES', label: '文件名净化' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFilenamesanitize: guard.evaluate,
  summarizeFilenamesanitize: guard.summarize,
  describeFilenamesanitize: guard.describe,
};
