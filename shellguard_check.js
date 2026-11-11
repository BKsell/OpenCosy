'use strict';

const { MAX_URL_LENGTH, MAX_MAILTO_ADDRS, MAX_TEL_DIGITS, DEFAULT_EXTERNAL_SCHEMES, EXECUTABLE_SUFFIXES, containsControlChar, containsEncodedControl, MAIL_TOKEN, reviewMailto, reviewTel, reviewExternalUrl, isExecutableName } = require('./shellguardreview');
const { safeParse } = require('./modutil');

// shellguard.js —— 交给系统 Shell 执行的“外部唤起”消毒内核。
//
// 威胁模型：
//   Electron 的 shell.openExternal(url) 最终落到平台 ShellExecute / xdg-open /
//   open，参数会被系统按协议处理器二次解析。即便外层已经把协议限制在 mailto/tel，
//   URL 本体仍然可控，存在这些面：
//     1) 控制字符 / CR / LF / Tab 注入：可在某些处理器里拆参数、注入附加头或新行；
//     2) URL 编码后的 %0d %0a %00 解码后同样是控制字符；
//     3) 过长字符串 / 畸形编码触发处理器边界缺陷；
//     4) mailto: 收件人地址里塞命令样字符、tel: 号码里塞分隔与控制序列；
//     5) Windows 上 file:// 指向 .exe/.lnk/.bat 等可执行或 UNC 路径，借“打开外部”
//        直接落程序执行。
//   shell.openPath / showItemInFolder 走的是本地路径，风险是路径穿越到下载目录外、
//   指向可执行文件被双击运行。本模块对两类输入统一做纯判定，不调用任何 Electron /
//   shell API，真实执行交给 main.js。

module.exports = {
  DEFAULT_EXTERNAL_SCHEMES,
  EXECUTABLE_SUFFIXES,
  MAIL_TOKEN,
  MAX_MAILTO_ADDRS,
  MAX_TEL_DIGITS,
  MAX_URL_LENGTH,
  containsControlChar,
  containsEncodedControl,
  isExecutableName,
  reviewExternalUrl,
  reviewMailto,
  reviewTel
};