'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ldapbind', prefix: 'LDAPBIND' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateLdapbindGuard: guard.evaluate,
  summarizeLdapbindGuard: guard.summarize,
  describeLdapbindGuard: guard.describe,
};
