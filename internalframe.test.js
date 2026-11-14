'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { frameHost, isInternalHostFrame, makeInternalFrameSender } = require('./internalframe_core');

function eventOf(url, sender) {
  return { sender, senderFrame: { url } };
}

test('frameHost only accepts cosy pages and returns their host name', () => {
  assert.equal(frameHost('cosy://taskmanager/index.html'), 'taskmanager');
  assert.equal(frameHost('cosy://readinglist'), 'readinglist');
  assert.equal(frameHost('https://example.com/'), null);
  assert.equal(frameHost('file:///C:/Windows/win.ini'), null);
  assert.equal(frameHost(''), null);
  assert.equal(frameHost(null), null);
  assert.equal(frameHost('not a url'), null);
});

test('isInternalHostFrame matches one host exactly', () => {
  assert.equal(isInternalHostFrame('cosy://about/', 'about'), true);
  assert.equal(isInternalHostFrame('cosy://about/', 'bookmarks'), false);
  assert.equal(isInternalHostFrame('cosy://about.evil/', 'about'), false);
  assert.equal(isInternalHostFrame('https://about/', 'about'), false);
  assert.equal(isInternalHostFrame('cosy://about/', ''), false);
  assert.equal(isInternalHostFrame('cosy://about/', null), false);
});

test('factory lets the shell window through', () => {
  const main = { id: 'shell' };
  const sender = makeInternalFrameSender({ host: 'history', isMainSender: (event) => event.sender === main });
  assert.equal(sender(eventOf('cosy://unrelated/', main)), true);
});

test('factory only lets the matching internal page through', () => {
  const sender = makeInternalFrameSender({ host: 'history', isMainSender: () => false });
  assert.equal(sender(eventOf('cosy://history/index.html', {})), true);
  assert.equal(sender(eventOf('cosy://bookmarks/index.html', {})), false);
  assert.equal(sender(eventOf('https://example.com/', {})), false);
  assert.equal(sender(eventOf('cosy://history.evil/', {})), false);
});

test('factory fails closed on missing frames and payloads', () => {
  const sender = makeInternalFrameSender({ host: 'pages', isMainSender: () => false });
  assert.equal(sender(null), false);
  assert.equal(sender({}), false);
  assert.equal(sender({ senderFrame: null }), false);
  assert.equal(sender({ senderFrame: { url: 42 } }), false);
  assert.equal(sender({ senderFrame: { url: '' } }), false);
  assert.equal(sender({ senderFrame: { url: 'cosy://pages/' } }), true);
});

test('factory without a host never authorizes a frame', () => {
  const sender = makeInternalFrameSender({ isMainSender: () => false });
  assert.equal(sender(eventOf('cosy://pages/', {})), false);
  assert.equal(makeInternalFrameSender()(eventOf('cosy://pages/', {})), false);
});
