'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ldap', prefix: 'LDAP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateLdapGuard: guard.evaluate,
  summarizeLdapGuard: guard.summarize,
  describeLdapGuard: guard.describe,
};
