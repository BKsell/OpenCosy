'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sendfile', prefix: 'SENDFILE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSendfileGuard: guard.evaluate,
  summarizeSendfileGuard: guard.summarize,
  describeSendfileGuard: guard.describe,
};
