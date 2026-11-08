'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'fileassociation', prefix: 'FILEASSOC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFileassociationGuard: guard.evaluate,
  summarizeFileassociationGuard: guard.summarize,
  describeFileassociationGuard: guard.describe,
};
