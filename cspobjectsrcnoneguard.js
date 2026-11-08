'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CSPOBJECT', label: 'CSP object-src directive' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspobjectsrcnoneGuard: guard.evaluate,
  describeCspobjectsrcnoneGuard: guard.describe,
};
