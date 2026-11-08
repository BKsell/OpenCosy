'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'RESPONSEH', label: 'Server 头剥离' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateResponseheaderstrip: guard.evaluate,
  summarizeResponseheaderstrip: guard.summarize,
  describeResponseheaderstrip: guard.describe,
};
