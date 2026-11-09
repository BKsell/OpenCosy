'use strict';

function create(ctx) {
  const {
    LOCAL_UI_CSP, acacGuard, acceptChGuard, acceptChLifetimeGuard, acceptCharsetGuard, acceptEncodingGuard,
    acceptLanguageGuard, acceptPatchGuard, acceptRangesGuard, ageClockGuard, allowHeaderGuard, allowHeadersGuard,
    allowMethodsGuard, altSvcGuard, applyCookieHardening, attributionGuard, authChallengeGuard, authenticationInfoGuard,
    baggageGuard, cacheAuthGuard, cacheStatusGuard, cacheVaryGuard, chMobileGuard, chPlatformGuard,
    charsetGuard, clearSiteDataGuard, coepGuard, connectionGuard, contentBaseGuard, contentDigestGuard,
    contentDispositionGuard, contentEncodingGuard, contentLanguageGuard, contentLocationGuard, contentMd5Guard, contentRangeGuard,
    contentTypeGuard, cookieJarGuard, coopGuard, corpGuard, corsGuard, credentialRequestGuard,
    criticalChGuard, crossDomainPolicyGuard, crossOriginPolicyGuard, cspReportOnlyGuard, digestGuard, dnsPrefetchGuard,
    dntGuard, documentPolicyGuard, downloadNameGuard, earlyHintGuard, etagGuard, expectCtGuard,
    expiresGuard, exposeHeadersGuard, featurePolicyGuard, fileSystemAccessGuard, forwardedGuard, fpGuard,
    frameOptionsGuard, headerBudgetGuard, headerInjectionGuard, hopByHopGuard, hstsGuard, ifMatchGuard,
    ifModifiedSinceGuard, ifNoneMatchGuard, ifRangeGuard, ifUnmodifiedSinceGuard, keepAliveGuard, lastModifiedGuard,
    legacyPinGuard, linkPreloadGuard, linkResponseGuard, maxAgeGuard, mimeExecGuard, nelReportGuard,
    noSniffGuard, noteGuardDenied, noteGuardResult, originAgentClusterGuard, originTrialGuard, permissionsPolicyGuard,
    pragmaCacheGuard, priorityGuard, protocol, proxyAuthGuard, proxyAuthenticateGuard, proxyStatusGuard,
    publicKeyPinsGuard, rangeGuard, recordFpHit, recordHeaderGrade, recordSecurityEvent, referrerPolicyGuard,
    refreshGuard, reportingEndpointsGuard, reportingGuard, retryAfterGuard, saveDataGuard, secFetchDestGuard,
    secFetchModeGuard, secFetchSiteGuard, secFetchUserGuard, secGpcGuard, secWebSocketGuard, securityBoundaryHub,
    securityHeadersGuard, serverBannerGuard, serverTimingGuard, serviceWorkerAllowedGuard, setCookie2Guard, setCookiePrefixGuard,
    sourceMapGuard, speculationRulesGuard, surrogateControlGuard, taoOriginGuard, teGuard, timingAllowOriginGuard,
    traceStateGuard, traceparentGuard, trailerFieldGuard, transferEncodingGuard, trueClientIpGuard, upgradeGuard,
    viaGuard, wantDigestGuard, warningHeaderGuard, wwwAuthenticateGuard, xContentTypeOptionsGuard, xDownloadOptionsGuard,
    xMethodOverrideGuard, xOriginalUrlGuard, xRealIpGuard, xRequestIdGuard, xRequestedWithGuard, xRobotsGuard,
    xWebKitCspGuard, xfwdForGuard, xfwdHostGuard, xfwdPortGuard, xfwdProtoGuard, xpcdpGuard,
    xssProtectionGuard, xuaCompatibleGuard,
  } = ctx;
  const readAllowPictureInPicture = ctx.readAllowPictureInPicture;
  const readStripAcceptCh = ctx.readStripAcceptCh;

  const headers = rawHeaders || {};
  const grade = !!(options && options.grade);
  // 安全头评级必须在下面任何 setIfMissing 之前完成，反映服务器原始姿态；
  // 只评远端顶层文档，不评我们自己强制注入的 cosy:// 页面与第三方子资源。
  if (grade && details.resourceType === 'mainFrame' && /^https?:/i.test(details.url)) {
    recordHeaderGrade(details.url, headers);
  }
  // 移除站点下发的 Accept-CH / Critical-CH：阻止其订阅高熵 Client Hints，
  // Critical-CH 还会触发带新头的重试，一并清掉以掐断放大通道。
  try {
    const removedCh = fpGuard.stripAcceptClientHints(headers, { stripAcceptCh: readStripAcceptCh() });
    if (removedCh.length) {
      recordFpHit(fpGuard.hostOf(details.url), 'accept-ch', removedCh);
    }
  } catch {}
  try {
    const hopResult = hopByHopGuard.applyHopByHopGuard(headers);
    if (hopResult.changed && grade) {
      recordSecurityEvent('protocol-blocked', 'warn',
        `hop:${hopResult.reason}`, fpGuard.hostOf(details.url));
    }
    const corsResult = corsGuard.applyCorsGuard(headers);
    if (corsResult.changed && grade) {
      recordSecurityEvent('origin-boundary-blocked', 'warn',
        `cors:${corsResult.verdict.reason}`, fpGuard.hostOf(details.url));
    }
    const authResult = authChallengeGuard.applyAuthChallengeGuard(headers, details);
    if (authResult.changed && grade) {
      recordSecurityEvent('auth-blocked', 'warn',
        `challenge:${authResult.verdict.reason}`, fpGuard.hostOf(details.url));
    }
    const mimeResult = mimeExecGuard.applyContentDispositionGuard(headers, details);
    if (mimeResult.changed && grade) {
      recordSecurityEvent('download-blocked', 'warn',
        `mime:${mimeResult.verdict.reason}`, fpGuard.hostOf(details.url));
    }
    const cacheResult = cacheVaryGuard.applyCacheVaryGuard(headers);
    if (cacheResult.changed && grade) {
      recordSecurityEvent('cookie-blocked', 'warn',
        `cache:${cacheResult.verdict.reason}`, fpGuard.hostOf(details.url));
    }
    const jarResult = cookieJarGuard.applyCookieJarHardening(headers);
    if (jarResult.changed && grade) {
      recordSecurityEvent('cookie-blocked', 'warn',
        `jar:${jarResult.verdict.reason}`, fpGuard.hostOf(details.url));
    }
    const nameResult = downloadNameGuard.applyDownloadNameGuard(headers);
    if (nameResult.changed && grade) {
      recordSecurityEvent('download-blocked', 'warn',
        `name:${nameResult.verdict.reason}`, fpGuard.hostOf(details.url));
    }
    const refreshResult = refreshGuard.applyRefreshHeaderGuard(headers, details);
    if (refreshResult.changed && grade) {
      recordSecurityEvent('origin-boundary-blocked', 'warn',
        `refresh:${refreshResult.findings[0].reason}`, fpGuard.hostOf(details.url));
    }
    const timingResult = serverTimingGuard.applyServerTimingGuard(headers, details);
    if (timingResult.changed && grade) {
      recordSecurityEvent('origin-boundary-blocked', 'warn',
        `timing:${timingResult.findings[0].reason}`, fpGuard.hostOf(details.url));
    }
    const rangeResult = contentRangeGuard.applyContentRangeGuard(headers);
    if (rangeResult.changed && grade) {
      recordSecurityEvent('download-blocked', 'warn',
        `range:${rangeResult.reason}`, fpGuard.hostOf(details.url));
    }
    const charsetResult = noteGuardResult('charset:', charsetGuard.applyCharsetGuard(headers), details.url, grade);
    const proxyAuthResult = proxyAuthGuard.applyProxyAuthGuard(headers, details);
    if (proxyAuthResult.changed && grade) {
      recordSecurityEvent('auth-blocked', 'warn',
        `proxy:${proxyAuthResult.findings[0].reason}`, fpGuard.hostOf(details.url));
    }
    const altSvcResult = altSvcGuard.applyAltSvcGuard(headers, details);
    if (altSvcResult.changed && grade) {
      recordSecurityEvent('origin-boundary-blocked', 'warn',
        `alt-svc:${altSvcResult.reason}`, fpGuard.hostOf(details.url));
    }

    const nelResult = nelReportGuard.applyReportingGuard(headers, details);
    if (nelResult.changed && grade) {
      recordSecurityEvent('origin-boundary-blocked', 'warn',
        `reporting:${nelResult.reason}`, fpGuard.hostOf(details.url));
    }
    const linkResult = linkPreloadGuard.applyLinkPreloadGuard(headers, details);
    if (linkResult.changed && grade) {
      recordSecurityEvent('origin-boundary-blocked', 'warn',
        `link:${linkResult.reason}`, fpGuard.hostOf(details.url));
    }
    const contentLocationResult = contentLocationGuard.applyContentLocationGuard(headers, details);
    if (contentLocationResult.changed && grade) {
      recordSecurityEvent('origin-boundary-blocked', 'warn',
        `content-location:${contentLocationResult.reason}`, fpGuard.hostOf(details.url));
    }
    const digestResult = digestGuard.applyDigestGuard(headers);
    if (digestResult.changed && grade) {
      recordSecurityEvent('protocol-blocked', 'warn',
        `digest:${digestResult.reason}`, fpGuard.hostOf(details.url));
    }
    const encodingResult = contentEncodingGuard.applyContentEncodingGuard(headers);
    if (encodingResult.changed && grade) {
      recordSecurityEvent('protocol-blocked', 'warn',
        `content-encoding:${encodingResult.reason}`, fpGuard.hostOf(details.url));
    }
    const legacyPinResult = legacyPinGuard.applyLegacyPinninguard(headers);
    if (legacyPinResult.changed && grade) {
      recordSecurityEvent('protocol-blocked', 'warn',
        `legacy-pin:${legacyPinResult.reason}`, fpGuard.hostOf(details.url));
    }
    const bannerResult = serverBannerGuard.applyServerBannerStripGuard(headers);
    if (bannerResult.changed && grade) {
      recordSecurityEvent('fingerprint-blocked', 'warn',
        `banner:${bannerResult.reason}`, fpGuard.hostOf(details.url));
    }
    const permissionsPolicyResult = permissionsPolicyGuard.applyPermissionsPolicyGuard(headers);
    if (permissionsPolicyResult.changed && grade) {
      recordSecurityEvent('origin-boundary-blocked', 'warn',
        `permissions-policy:${permissionsPolicyResult.reason}`, fpGuard.hostOf(details.url));
    }
    const frameOptionsResult = frameOptionsGuard.applyFrameOptionsGuard(headers);
    if (frameOptionsResult.changed && grade) {
      recordSecurityEvent('origin-boundary-blocked', 'warn',
        `x-frame-options:${frameOptionsResult.reason}`, fpGuard.hostOf(details.url));
    }
    const contentDispositionResult = contentDispositionGuard.applyContentDispositionGuard(headers);
    if (contentDispositionResult.changed && grade) {
      recordSecurityEvent('download-blocked', 'warn',
        `content-disposition:${contentDispositionResult.reason}`, fpGuard.hostOf(details.url));
    }
    const cacheAuthResult = cacheAuthGuard.applyAuthCacheGuard(headers);
    if (cacheAuthResult.changed && grade) {
      recordSecurityEvent('auth-blocked', 'warn',
        `cache-auth:${cacheAuthResult.reason}`, fpGuard.hostOf(details.url));
    }
    const xssProtectionResult = xssProtectionGuard.applyXSSProtectionGuard(headers);
    if (xssProtectionResult.changed && grade) {
      recordSecurityEvent('protocol-blocked', 'warn',
        `x-xss-protection:${xssProtectionResult.reason}`, fpGuard.hostOf(details.url));
    }
    const clearSiteDataResult = clearSiteDataGuard.applyClearSiteDataGuard(headers);
    if (clearSiteDataResult.changed && grade) {
      recordSecurityEvent('storage-cross-access', 'warn',
        `clear-site-data:${clearSiteDataResult.reason}`, fpGuard.hostOf(details.url));
    }
    const serviceWorkerAllowedResult = serviceWorkerAllowedGuard.applyServiceWorkerAllowedGuard(headers);
    if (serviceWorkerAllowedResult.changed && grade) {
      recordSecurityEvent('origin-boundary-blocked', 'warn',
        `service-worker-allowed:${serviceWorkerAllowedResult.reason}`, fpGuard.hostOf(details.url));
    }
    const referrerPolicyResult = referrerPolicyGuard.applyReferrerPolicyGuard(headers);
    if (referrerPolicyResult.changed && grade) {
      recordSecurityEvent('origin-boundary-blocked', 'warn',
        `referrer-policy:${referrerPolicyResult.reason}`, fpGuard.hostOf(details.url));
    }
    const crossOriginPolicyResult = crossOriginPolicyGuard.applyCrossOriginPolicyGuard(headers);
    if (crossOriginPolicyResult.changed && grade) {
      recordSecurityEvent('origin-boundary-blocked', 'warn',
        `cross-origin-policy:${(crossOriginPolicyResult.findings[0] || {}).reason || 'ok'}`, fpGuard.hostOf(details.url));
    }
    const setCookiePrefixResult = setCookiePrefixGuard.applySetCookiePrefixGuard(headers);
    if (setCookiePrefixResult.changed && grade) {
      recordSecurityEvent('storage-cross-access', 'warn',
        `set-cookie-prefix:${setCookiePrefixResult.reason}`, fpGuard.hostOf(details.url));
    }
    const retryAfterResult = retryAfterGuard.applyRetryAfterGuard(headers);
    if (retryAfterResult.changed && grade) {
      recordSecurityEvent('protocol-blocked', 'warn',
        `retry-after:${retryAfterResult.reason}`, fpGuard.hostOf(details.url));
    }
    const xContentTypeOptionsResult = xContentTypeOptionsGuard.applyXContentTypeOptionsGuard(headers);
    if (xContentTypeOptionsResult.changed && grade) {
      recordSecurityEvent('protocol-blocked', 'warn',
        `x-content-type-options:${xContentTypeOptionsResult.reason}`, fpGuard.hostOf(details.url));
    }
    const wwwAuthenticateResult = wwwAuthenticateGuard.applyWwwAuthenticateGuard(headers, 'WWW-Authenticate');
    if (wwwAuthenticateResult.changed && grade) {
      recordSecurityEvent('auth-blocked', 'warn',
        `www-authenticate:${wwwAuthenticateResult.reason}`, fpGuard.hostOf(details.url));
    }
    const proxyAuthenticateResult = wwwAuthenticateGuard.applyWwwAuthenticateGuard(headers, 'Proxy-Authenticate');
    if (proxyAuthenticateResult.changed && grade) {
      recordSecurityEvent('auth-blocked', 'warn',
        `proxy-authenticate:${proxyAuthenticateResult.reason}`, fpGuard.hostOf(details.url));
    }
    const timingAllowOriginResult = timingAllowOriginGuard.applyTimingAllowOriginGuard(headers);
    if (timingAllowOriginResult.changed && grade) {
      recordSecurityEvent('origin-boundary-blocked', 'warn',
        `timing-allow-origin:${timingAllowOriginResult.reason}`, fpGuard.hostOf(details.url));
    }
    const headerInjectionResult = headerInjectionGuard.applyHeaderInjectionGuard(headers);
    if (headerInjectionResult.changed && grade) {
      recordSecurityEvent('protocol-blocked', 'warn',
        `header-injection:${headerInjectionResult.reason}`, fpGuard.hostOf(details.url));
    }
    const documentPolicyResult = noteGuardResult('document-policy:', documentPolicyGuard.applyDocumentPolicyGuard(headers), details.url, grade);
    const contentDigestResult = noteGuardResult('content-digest:', contentDigestGuard.applyContentDigestGuard(headers), details.url, grade);
    const reprDigestResult = noteGuardResult('repr-digest:', contentDigestGuard.applyReprDigestGuard(headers), details.url, grade);
    const cacheStatusResult = noteGuardResult('cache-status:', cacheStatusGuard.applyCacheStatusGuard(headers), details.url, grade);
    const etagResult = noteGuardResult('etag:', etagGuard.applyETagGuard(headers), details.url, grade);
    const trailerFieldResult = noteGuardResult('trailer:', trailerFieldGuard.applyTrailerFieldGuard(headers), details.url, grade);
    const secWebSocketAcceptResult = noteGuardResult('websocket-accept:', secWebSocketGuard.applySecWebSocketAcceptGuard(headers), details.url, grade);
    const secWebSocketProtocolResult = noteGuardResult('websocket-protocol:', secWebSocketGuard.applySecWebSocketProtocolGuard(headers), details.url, grade);
    const xDownloadOptionsResult = noteGuardResult('x-download-options:', xDownloadOptionsGuard.applyXDownloadOptionsGuard(headers), details.url, grade);
    const fileSystemAccessResult = noteGuardDenied('file-system-access:', fileSystemAccessGuard.inspectFileSystemAccess(details.url), details.url, grade);
    const credentialRequestResult = noteGuardDenied('credential-request:', credentialRequestGuard.inspectCredentialRequest(details.url), details.url, grade);
    if (grade) {
      const priorityResult = noteGuardResult('priority:', priorityGuard.applyPriorityGuard(headers), details.url, true);
      const linkResponseResult = noteGuardResult('link:', linkResponseGuard.applyLinkResponseGuard(headers, details.url), details.url, true);
      const acceptPatchResult = noteGuardResult('accept-patch:', acceptPatchGuard.applyAcceptPatchGuard(headers), details.url, true);
      const speculationRulesResult = noteGuardResult('speculation-rules:', speculationRulesGuard.applySpeculationRulesGuard(headers, details.url), details.url, true);
      const proxyStatusResult = noteGuardResult('proxy-status:', proxyStatusGuard.applyProxyStatusGuard(headers), details.url, true);
      const acceptCharsetResult = noteGuardResult('accept-charset:', acceptCharsetGuard.applyAcceptCharsetGuard(headers), details.url, true);
      const reportingEndpointsResult = noteGuardResult('reporting-endpoints:', reportingGuard.applyReportingEndpointsGuard(headers), details.url, true);
      const reportToResult = noteGuardResult('report-to:', reportingGuard.applyReportToGuard(headers), details.url, true);
      const upgradeResult = noteGuardResult('upgrade:', upgradeGuard.applyUpgradeHeaderGuard(headers), details.url, true);
      const expectCtResult = noteGuardResult('expect-ct:', expectCtGuard.applyExpectCtGuard(headers), details.url, true);
      const publicKeyPinsResult = noteGuardResult('public-key-pins:', publicKeyPinsGuard.applyPublicKeyPinsGuard(headers), details.url, true);
      const originTrialResult = noteGuardResult('origin-trial:', originTrialGuard.applyOriginTrialGuard(headers, details.url), details.url, true);
      const coepGuardResult = noteGuardResult('coep:', coepGuard.applyCoepGuard(headers), details.url, true);
      const cspReportOnlyGuardResult = noteGuardResult('csp-report-only:', cspReportOnlyGuard.applyCspReportOnlyGuard(headers), details.url, true);
      const xpcdpGuardResult = noteGuardResult('x-permitted-cross-domain-policies:', xpcdpGuard.applyXpcdpGuard(headers), details.url, true);
      const acacGuardResult = noteGuardResult('cors-credentials:', acacGuard.applyAcacGuard(headers), details.url, true);
      const secGpcGuardResult = noteGuardResult('sec-gpc:', secGpcGuard.applySecGpcGuard(headers), details.url, true);
      const dntGuardResult = noteGuardResult('dnt:', dntGuard.applyDntGuard(headers), details.url, true);
      const acceptLanguageGuardResult = noteGuardResult('accept-language:', acceptLanguageGuard.applyAcceptLanguageGuard(headers), details.url, true);
      const ifNoneMatchGuardResult = noteGuardResult('if-none-match:', ifNoneMatchGuard.applyIfNoneMatchGuard(headers), details.url, true);
      const rangeGuardResult = noteGuardResult('range:', rangeGuard.applyRangeGuard(headers), details.url, true);
      const connectionGuardResult = noteGuardResult('connection:', connectionGuard.applyConnectionGuard(headers), details.url, true);
      const teGuardResult = noteGuardResult('te:', teGuard.applyTeGuard(headers), details.url, true);
      const viaGuardResult = noteGuardResult('via:', viaGuard.applyViaGuard(headers), details.url, true);
      const forwardedGuardResult = noteGuardResult('forwarded:', forwardedGuard.applyForwardedGuard(headers), details.url, true);
      const secFetchSiteGuardResult = noteGuardResult('sec-fetch-site:', secFetchSiteGuard.applySecFetchSiteGuard(headers), details.url, true);
      const sourceMapGuardResult = noteGuardResult('sourcemap:', sourceMapGuard.applySourceMapGuard(headers), details.url, true);
      const attributionGuardResult = noteGuardResult('attribution-reporting:', attributionGuard.applyAttributionGuard(headers), details.url, true);
      const reportingEndpointsGuardResult = noteGuardResult('reporting-endpoints:', reportingEndpointsGuard.applyReportingEndpointsGuard(headers), details.url, true);
      const noSniffGuardResult = noteGuardResult('nosniff:', noSniffGuard.applyNoSniffGuard(headers), details.url, true);
      const xRequestIdGuardResult = noteGuardResult('x-request-id:', xRequestIdGuard.applyXRequestIdGuard(headers), details.url, true);
      const traceparentGuardResult = noteGuardResult('traceparent:', traceparentGuard.applyTraceparentGuard(headers), details.url, true);
      const saveDataGuardResult = noteGuardResult('save-data:', saveDataGuard.applySaveDataGuard(headers), details.url, true);
      const trueClientIpGuardResult = noteGuardResult('true-client-ip:', trueClientIpGuard.applyTrueClientIpGuard(headers), details.url, true);
      const xRealIpGuardResult = noteGuardResult('x-real-ip:', xRealIpGuard.applyXRealIpGuard(headers), details.url, true);
      const acceptEncodingGuardResult = noteGuardResult('accept-encoding:', acceptEncodingGuard.applyAcceptEncodingGuard(headers), details.url, true);
      const exposeHeadersGuardResult = noteGuardResult('exposeheaders:', exposeHeadersGuard.applyExposeHeadersGuard(headers), details.url, true);
      const maxAgeGuardResult = noteGuardResult('maxage:', maxAgeGuard.applyMaxAgeGuard(headers), details.url, true);
      const allowMethodsGuardResult = noteGuardResult('allowmethods:', allowMethodsGuard.applyAllowMethodsGuard(headers), details.url, true);
      const allowHeadersGuardResult = noteGuardResult('allowheaders:', allowHeadersGuard.applyAllowHeadersGuard(headers), details.url, true);
      const coopGuardResult = noteGuardResult('coop:', coopGuard.applyCoopGuard(headers), details.url, true);
      const secFetchModeGuardResult = noteGuardResult('secfetchmode:', secFetchModeGuard.applySecFetchModeGuard(headers), details.url, true);
      const secFetchDestGuardResult = noteGuardResult('secfetchdest:', secFetchDestGuard.applySecFetchDestGuard(headers), details.url, true);
      const secFetchUserGuardResult = noteGuardResult('secfetchuser:', secFetchUserGuard.applySecFetchUserGuard(headers), details.url, true);
      const chPlatformGuardResult = noteGuardResult('chplatform:', chPlatformGuard.applyChPlatformGuard(headers), details.url, true);
      const chMobileGuardResult = noteGuardResult('chmobile:', chMobileGuard.applyChMobileGuard(headers), details.url, true);
      const ifMatchGuardResult = noteGuardResult('ifmatch:', ifMatchGuard.applyIfMatchGuard(headers), details.url, true);
      const ifRangeGuardResult = noteGuardResult('ifrange:', ifRangeGuard.applyIfRangeGuard(headers), details.url, true);
      const ifModifiedSinceGuardResult = noteGuardResult('ifmodifiedsince:', ifModifiedSinceGuard.applyIfModifiedSinceGuard(headers), details.url, true);
      const ifUnmodifiedSinceGuardResult = noteGuardResult('ifunmodifiedsince:', ifUnmodifiedSinceGuard.applyIfUnmodifiedSinceGuard(headers), details.url, true);
      const contentTypeGuardResult = noteGuardResult('contenttype:', contentTypeGuard.applyContentTypeGuard(headers), details.url, true);
      const allowHeaderGuardResult = noteGuardResult('allow:', allowHeaderGuard.applyAllowGuard(headers), details.url, true);
      const expiresGuardResult = noteGuardResult('expires:', expiresGuard.applyExpiresGuard(headers), details.url, true);
      const earlyHintGuardResult = noteGuardResult('earlyhint:', earlyHintGuard.applyEarlyHintGuard(headers), details.url, true);
      const traceStateGuardResult = noteGuardResult('tracestate:', traceStateGuard.applyTraceStateGuard(headers), details.url, true);
      const baggageGuardResult = noteGuardResult('baggage:', baggageGuard.applyBaggageGuard(headers), details.url, true);
      const xfwdProtoGuardResult = noteGuardResult('xforwardedproto:', xfwdProtoGuard.applyXForwardedProtoGuard(headers), details.url, true);
      const xfwdHostGuardResult = noteGuardResult('xforwardedhost:', xfwdHostGuard.applyXForwardedHostGuard(headers), details.url, true);
      const xfwdForGuardResult = noteGuardResult('xforwardedfor:', xfwdForGuard.applyXForwardedForGuard(headers), details.url, true);
      const featurePolicyGuardResult = noteGuardResult('featurepolicy:', featurePolicyGuard.applyFeaturePolicyGuard(headers), details.url, true);
      const criticalChGuardResult = noteGuardResult('criticalch:', criticalChGuard.applyCriticalChGuard(headers), details.url, true);
      const wantDigestGuardResult = noteGuardResult('wantdigest:', wantDigestGuard.applyWantDigestGuard(headers), details.url, true);
      const corpGuardResult = noteGuardResult('corp:', corpGuard.applyCorpGuard(headers), details.url, true);
      const xfwdPortGuardResult = noteGuardResult('xforwardedport:', xfwdPortGuard.applyXForwardedPortGuard(headers), details.url, true);
      const taoOriginGuardResult = noteGuardResult('timingalloworigin:', taoOriginGuard.applyTimingAllowOriginGuard(headers), details.url, true);
      const proxyAuthenticateGuardResult = noteGuardResult('proxyauthenticate:', proxyAuthenticateGuard.applyProxyAuthenticateGuard(headers), details.url, true);
      const xRequestedWithGuardResult = noteGuardResult('xrequestedwith:', xRequestedWithGuard.applyXRequestedWithGuard(headers), details.url, true);
      const xMethodOverrideGuardResult = noteGuardResult('xhttpmethodoverride:', xMethodOverrideGuard.applyXHttpMethodOverrideGuard(headers), details.url, true);
      const xOriginalUrlGuardResult = noteGuardResult('xoriginalurl:', xOriginalUrlGuard.applyXOriginalUrlGuard(headers), details.url, true);
      const responseSurfaceAudit = securityBoundaryHub.inspectResponseHeaders(headers, fpGuard.hostOf(details.url));
      if (responseSurfaceAudit.changed) {
        recordSecurityEvent('mixed-content-blocked', 'warn',
          `response-surface:${securityBoundaryHub.describeFindings(responseSurfaceAudit.findings)}`,
          fpGuard.hostOf(details.url));
      }
      const acceptChLifetimeResult = noteGuardResult('accept-ch-lifetime:', acceptChLifetimeGuard.applyAcceptChLifetimeGuard(headers), details.url, true);
      const securityHeadersAudit = securityHeadersGuard.auditHeaderBatch([{ url: details.url, headers }]);
      if (securityHeadersAudit.weak > 0) {
        recordSecurityEvent('mixed-content-blocked', 'warn',
          `security-headers:${securityHeadersGuard.describeFindings(securityHeadersAudit.findings)}`,
          fpGuard.hostOf(details.url));
      }
      const xuaCompatibleResult = noteGuardResult('x-ua-compatible:', xuaCompatibleGuard.applyXuaCompatibleGuard(headers), details.url, true);
      const acceptRangesResult = noteGuardResult('accept-ranges:', acceptRangesGuard.applyAcceptRangesGuard(headers), details.url, true);
      const contentBaseResult = noteGuardResult('content-base:', contentBaseGuard.applyContentBaseGuard(headers), details.url, true);
      const contentMd5Result = noteGuardResult('content-md5:', contentMd5Guard.applyContentMd5Guard(headers), details.url, true);
      const pragmaCacheResult = noteGuardResult('pragma:', pragmaCacheGuard.applyPragmaCacheGuard(headers), details.url, true);
      const xRobotsResult = noteGuardResult('x-robots-tag:', xRobotsGuard.applyXRobotsGuard(headers), details.url, true);
      const surrogateControlResult = noteGuardResult('surrogate-control:', surrogateControlGuard.applySurrogateControlGuard(headers), details.url, true);
      const setCookie2Result = noteGuardResult('set-cookie2:', setCookie2Guard.applySetCookie2Guard(headers), details.url, true);
      const xWebKitCspResult = noteGuardResult('x-webkit-csp:', xWebKitCspGuard.applyXWebKitCspGuard(headers), details.url, true);
      const authenticationInfoResult = noteGuardResult('authentication-info:', authenticationInfoGuard.applyAuthenticationInfoGuard(headers), details.url, true);
      const originAgentClusterResult = noteGuardResult('origin-agent-cluster:', originAgentClusterGuard.applyOriginAgentClusterGuard(headers), details.url, true);
      const ageClockResult = noteGuardResult('age:', ageClockGuard.applyAgeClockGuard(headers), details.url, true);
      const warningHeaderResult = noteGuardResult('warning:', warningHeaderGuard.applyWarningHeaderGuard(headers), details.url, true);
      const contentLanguageResult = noteGuardResult('content-language:', contentLanguageGuard.applyContentLanguageGuard(headers), details.url, true);
      const lastModifiedResult = noteGuardResult('last-modified:', lastModifiedGuard.applyLastModifiedGuard(headers), details.url, true);
      const dnsPrefetchResult = noteGuardResult('x-dns-prefetch-control:', dnsPrefetchGuard.applyDnsPrefetchGuard(headers), details.url, true);
      const headerBudgetResult = noteGuardResult('header-budget:', headerBudgetGuard.applyHeaderBudgetGuard(headers), details.url, true);
      const acceptChResult = noteGuardResult('accept-ch:', acceptChGuard.applyAcceptChGuard(headers), details.url, true);
      const keepAliveResult = noteGuardResult('keep-alive:', keepAliveGuard.applyKeepAliveGuard(headers), details.url, true);
      const crossDomainPolicyResult = noteGuardResult('x-permitted-cross-domain-policies:', crossDomainPolicyGuard.applyCrossDomainPolicyGuard(headers), details.url, true);
      const transferEncodingResult = noteGuardResult('content-transfer-encoding:', transferEncodingGuard.applyTransferEncodingGuard(headers), details.url, true);
      const hstsResult = noteGuardResult('hsts:', hstsGuard.applyHstsGuard(headers), details.url, true);
    }
  } catch {}
  const setIfMissing = (name, value) => {
    if (!headers[name] && !headers[name.toLowerCase()]) headers[name] = value;
  };
  setIfMissing('X-Content-Type-Options', ['nosniff']);
  setIfMissing('X-Frame-Options', ['SAMEORIGIN']);
  setIfMissing('Referrer-Policy', ['strict-origin-when-cross-origin']);
  // 关闭 FLoC / 广告兴趣组 / Topics / 隐私令牌等追踪特性。
  // 指令由 permpolicy 内核统一构建（强制关闭项不可被放开，白名单防头注入）；
  // 站点未自行下发策略时注入默认值，尊重站点对其它能力的显式配置。
  // 画中画按用户隐私开关显式给出 picture-in-picture 指令（放开 * / 全禁 ()）。
  setIfMissing('Permissions-Policy', [permPolicy.headerWithPictureInPicture(readAllowPictureInPicture())]);
  const isLocal = details.url.startsWith('cosy://') || details.url.startsWith('file://');
  if (isLocal && !headers['Content-Security-Policy'] && !headers['content-security-policy']) {
    headers['Content-Security-Policy'] = [LOCAL_UI_CSP];
  }
  // 本地页面（cosy:// / file://）加 COOP/COEP/CORP，跨源资源进不来，
  // 防止恶意网页把我们的设置页 / 下载页 iframe 化后读内容（Spectre 类侧信道）。
  if (isLocal) {
    headers['Cross-Origin-Opener-Policy'] = ['same-origin'];
    headers['Cross-Origin-Embedder-Policy'] = ['require-corp'];
    headers['Cross-Origin-Resource-Policy'] = ['same-origin'];
  }
  // HTTPS 响应默认补 HSTS，让浏览器后续访问自动升级（1 年 + includeSubDomains）。
  // 已经自带 HSTS 的站点不覆盖。
  if (details.url.startsWith('https://') &&
      !headers['Strict-Transport-Security'] && !headers['strict-transport-security']) {
    headers['Strict-Transport-Security'] = ['max-age=31536000; includeSubDomains'];
  }
  // Cookie 加固放在所有响应头处理之后、回写之前：剥离第三方 / 非法前缀 /
  // http 下 Secure 的 Set-Cookie，并为第一方 Cookie 补 SameSite=Lax。
  // 仅处理 http(s) 响应，内部 cosy:// 页面不种浏览器 Cookie。
  if (/^https?:/i.test(details.url)) {
    applyCookieHardening(headers, details);
  }
  return headers;

  return { hardenResponseHeaders };
}

module.exports = { create };
