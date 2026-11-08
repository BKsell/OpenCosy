'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'imap', prefix: 'IMAP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateImapGuard: guard.evaluate,
  summarizeImapGuard: guard.summarize,
  describeImapGuard: guard.describe,
};
