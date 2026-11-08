'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'STYLEUNSA', label: '内联样式禁用' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateStyleunsafeinlineforbid: guard.evaluate,
  summarizeStyleunsafeinlineforbid: guard.summarize,
  describeStyleunsafeinlineforbid: guard.describe,
};
