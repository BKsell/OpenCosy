'use strict';

function frameHost(frameUrl) {
  if (typeof frameUrl !== 'string' || frameUrl === '') return null;
  let parsed = null;
  try {
    parsed = new URL(frameUrl);
  } catch {
    return null;
  }
  if (!parsed || parsed.protocol !== 'cosy:') return null;
  return parsed.hostname;
}

function isInternalHostFrame(frameUrl, host) {
  if (typeof host !== 'string' || host === '') return false;
  return frameHost(frameUrl) === host;
}

function makeInternalFrameSender(options) {
  const isMainSender = options && options.isMainSender;
  const host = options && options.host;
  return function internalFrameSender(event) {
    if (typeof isMainSender === 'function' && isMainSender(event)) return true;
    const frame = event && event.senderFrame;
    if (!frame || typeof frame.url !== 'string') return false;
    return isInternalHostFrame(frame.url, host);
  };
}

module.exports = { frameHost, isInternalHostFrame, makeInternalFrameSender };
