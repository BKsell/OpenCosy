'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'calendarwd', prefix: 'CALENDARW' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCalendarwdGuard: guard.evaluate,
  summarizeCalendarwdGuard: guard.summarize,
  describeCalendarwdGuard: guard.describe,
};
