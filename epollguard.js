'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'epoll', prefix: 'EPOLL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEpollGuard: guard.evaluate,
  summarizeEpollGuard: guard.summarize,
  describeEpollGuard: guard.describe,
};
