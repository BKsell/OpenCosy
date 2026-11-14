'use strict';

const ERROR_TABLE = {
  '-105': { status: '404', message: '无法找到服务器', text: 'ERR_NAME_NOT_RESOLVED' },
  '-106': { status: '400', message: '网络连接已断开', text: 'ERR_INTERNET_DISCONNECTED' },
  '-102': { status: '404', message: '连接被拒绝', text: 'ERR_CONNECTION_REFUSED' },
  '-109': { status: '404', message: '地址无法访问', text: 'ERR_ADDRESS_UNREACHABLE' },
  '-118': { status: '404', message: '连接超时', text: 'ERR_CONNECTION_TIMED_OUT' },
  '-324': { status: '500', message: '服务器返回空响应', text: 'ERR_EMPTY_RESPONSE' },
  '-501': { status: '501', message: '不安全的响应', text: 'ERR_INSECURE_RESPONSE' },
  '-6': { status: '404', message: '文件未找到', text: 'ERR_FILE_NOT_FOUND' },
  '-3': { status: '403', message: '访问被拒绝', text: 'ERR_ACCESS_DENIED' }
};

function errorEntry(errorCode) {
  if (errorCode === null || errorCode === undefined) return null;
  return ERROR_TABLE[String(errorCode)] || null;
}

function getHttpStatusCode(errorCode) {
  const entry = errorEntry(errorCode);
  return entry ? entry.status : '500';
}

function getErrorMessage(errorCode) {
  const entry = errorEntry(errorCode);
  return entry ? entry.message : '发生未知错误';
}

function getBrowserErrorText(errorCode) {
  const entry = errorEntry(errorCode);
  return entry ? entry.text : 'UNKNOWN_ERROR';
}

function isValidColor(str) {
  return typeof str === 'string' && /^#[0-9a-fA-F]{3,8}$/.test(str);
}

module.exports = { getHttpStatusCode, getErrorMessage, getBrowserErrorText, isValidColor };
