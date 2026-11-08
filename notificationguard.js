'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'notification', prefix: 'NOTIFICAT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNotificationGuard: guard.evaluate,
  summarizeNotificationGuard: guard.summarize,
  describeNotificationGuard: guard.describe,
};
