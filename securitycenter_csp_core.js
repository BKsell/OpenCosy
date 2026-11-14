const { securityEventStorePath, MAX_SECURITY_EVENTS, MAX_SECURITY_DETAIL_CHARS, SECURITY_EVENT_TYPES, securityEvents, securityEventsLoaded, securityEventSaveTimer, loadSecurityEvents, persistSecurityEvents, sanitizeSecurityDetail, recordSecurityEvent, listSecurityEvents, clearSecurityEvents } = require('./cspsecurityevents_core');
const { app } = require('electron');
const path = require('path');
const fsSync = require('fs');
const ledgerStore = require('./ledgerstore_core');


let sendToRenderer = () => {};

function bindRendererNotifier(fn) {
  if (typeof fn === 'function') sendToRenderer = fn;
}


const cspReportStorePath = path.join(app.getPath('userData'), 'csp-reports.json');
const MAX_CSP_REPORTS = 500;
const CSP_RATE_WINDOW_MS = 10_000;
const CSP_RATE_MAX_PER_WINDOW = 20;

module.exports = {
  sendToRenderer,
  bindRendererNotifier,
  securityEventStorePath,
  MAX_SECURITY_EVENTS,
  MAX_SECURITY_DETAIL_CHARS,
  SECURITY_EVENT_TYPES,
  securityEvents,
  securityEventsLoaded,
  securityEventSaveTimer,
  loadSecurityEvents,
  persistSecurityEvents,
  sanitizeSecurityDetail,
  recordSecurityEvent,
  listSecurityEvents,
  clearSecurityEvents,
  cspReportStorePath,
  MAX_CSP_REPORTS,
  CSP_RATE_WINDOW_MS,
  CSP_RATE_MAX_PER_WINDOW,
};
