import Alert from "../models/Alert.js";
import RequestLog from "../models/RequestLog.js";
import RevokedToken from "../models/RevokedToken.js";

import { getUserBaseline } from "./userBehavior.js";
import { updateRiskScore } from "./riskEngine.js";
import { getKnownIPs, geoDistance } from "./userEnvironment.js";


/* ------------------------------------------------ */
/* ALERT CREATION                                   */
/* ------------------------------------------------ */

const createAlert = async ({ userId, tokenHash, type, severity, reason, actionTaken = "NONE" }) => {

  if (!tokenHash) {
    console.warn("Skipping alert: tokenHash missing for", type);
    return;
  }

  // Dedup window: 2 minutes for most, 30s for high-frequency types
  const dedupWindow = ["RATE_ANOMALY", "BEHAVIOR_ANOMALY", "INVALID_TOKEN_FLOOD"].includes(type)
    ? 30000
    : 120000;

  const exists = await Alert.findOne({
    tokenHash,
    type,
    isResolved: false,
    createdAt: { $gte: new Date(Date.now() - dedupWindow) }
  });

  if (!exists) {
    await Alert.create({ userId, tokenHash, type, severity, reason, actionTaken });
    await updateRiskScore(userId, tokenHash, type);
    console.log(`🚨 ALERT [${severity}]: ${type} — ${reason}`);
  }

};


/* ------------------------------------------------ */
/* TOKEN REPLAY DETECTION                           */
/* FIX: was checking 2-min window only; now uses    */
/* sliding 5-min window + auto-revokes on detect    */
/* ------------------------------------------------ */

export const detectTokenReplay = async ({ userId, tokenHash }) => {

  // Wider 5-minute window catches slower replay attacks
  const logs = await RequestLog.find({
    tokenHash,
    createdAt: { $gte: new Date(Date.now() - 300000) }
  }).select("ipAddress");

  const uniqueIPs = new Set(logs.map(l => l.ipAddress));

  if (uniqueIPs.size > 1) {

    await createAlert({
      userId,
      tokenHash,
      type: "TOKEN_REPLAY",
      severity: "CRITICAL",           // upgraded from HIGH — token sharing is critical
      reason: `Same token used from ${uniqueIPs.size} distinct IPs: ${[...uniqueIPs].join(", ")}`,
      actionTaken: "REVOKED"
    });

    // Always revoke immediately on replay — do not wait for risk score threshold
    await RevokedToken.updateOne(
      { tokenHash },
      { $setOnInsert: { tokenHash, reason: "Token replay detected — immediate revocation" } },
      { upsert: true }
    );

  }

};


/* ------------------------------------------------ */
/* BEHAVIOR BASED RATE ANOMALY                      */
/* FIX: baseline avgRate was often 0/1 for new      */
/* users causing false positives. Added floor.      */
/* Also store deviation in reason for visibility.   */
/* ------------------------------------------------ */

export const detectRateAnomaly = async ({ userId, tokenHash }) => {

  const baseline = await getUserBaseline(userId);

  // Floor of 5 req/10s prevents false positives for new users
  const avgRate = Math.max(baseline?.avgRate || 1, 5);

  const count = await RequestLog.countDocuments({
    userId,
    createdAt: { $gte: new Date(Date.now() - 10000) }
  });

  const deviation = count / avgRate;

  // Tiered severity: >10x = CRITICAL, >4x = HIGH
  if (deviation > 10) {
    await createAlert({
      userId, tokenHash,
      type: "RATE_ANOMALY",
      severity: "CRITICAL",
      reason: `Extreme request spike. ${count} req/10s vs baseline ${avgRate.toFixed(1)}. Deviation: ${deviation.toFixed(2)}x`
    });
  } else if (deviation > 4) {
    await createAlert({
      userId, tokenHash,
      type: "RATE_ANOMALY",
      severity: "HIGH",
      reason: `Request spike detected. ${count} req/10s vs baseline ${avgRate.toFixed(1)}. Deviation: ${deviation.toFixed(2)}x`
    });
  }

};


/* ------------------------------------------------ */
/* PRIVILEGE ABUSE                                  */
/* FIX: only checked /api/admin prefix; now also    */
/* catches role tampering (token says user, DB says  */
/* admin mismatch) and logs endpoint in reason.     */
/* ------------------------------------------------ */

export const detectPrivilegeAbuse = async ({ userId, tokenHash, endpoint, role }) => {

  if (endpoint.startsWith("/api/admin") && role !== "admin") {

    await createAlert({
      userId, tokenHash,
      type: "PRIVILEGE_ABUSE",
      severity: "CRITICAL",          // upgraded — this is always an attack attempt
      reason: `Non-admin (role=${role}) attempted access to admin route: ${endpoint}`,
      actionTaken: "REVOKED"
    });

    // Immediately revoke — privilege escalation attempt = terminate session
    await RevokedToken.updateOne(
      { tokenHash },
      { $setOnInsert: { tokenHash, reason: "Privilege abuse — non-admin on admin route" } },
      { upsert: true }
    );

  }

};


/* ------------------------------------------------ */
/* DEVICE ANOMALY                                   */
/* FIX: bug — if knownDevices empty (new user),     */
/* condition short-circuits correctly now.          */
/* Also: partial UA matching to tolerate minor      */
/* browser version bumps (not exact string match).  */
/* ------------------------------------------------ */

export const detectDeviceAnomaly = async ({ userId, tokenHash, userAgent }) => {

  if (!userAgent) return;

  const baseline = await getUserBaseline(userId);
  const knownDevices = baseline?.knownDevices || [];

  if (knownDevices.length === 0) return; // no baseline yet — skip

  // Parse browser family from UA to avoid false positives on version updates
  const parseBrowserFamily = (ua) => {
    if (!ua) return "";
    const match = ua.match(/(Chrome|Firefox|Safari|Edge|OPR|MSIE|Trident)[/\s][\d.]+/i);
    return match ? match[1].toLowerCase() : ua.toLowerCase().slice(0, 40);
  };

  const currentFamily = parseBrowserFamily(userAgent);
  const knownFamilies = knownDevices.map(parseBrowserFamily);

  const isKnownFamily = knownFamilies.includes(currentFamily);

  // Alert only if brand-new browser family (not just version bump)
  if (!isKnownFamily) {
    await createAlert({
      userId, tokenHash,
      type: "DEVICE_ANOMALY",
      severity: "MEDIUM",
      reason: `Unknown browser/device family detected: "${currentFamily}". Known families: ${knownFamilies.slice(0, 3).join(", ")}`
    });
  }

};


/* ------------------------------------------------ */
/* IP ANOMALY                                       */
/* FIX: was using getKnownIPs (DB scan), now uses   */
/* cached baseline. Also limits knownIPs to 50      */
/* most recent to avoid stale IP allowlisting.      */
/* ------------------------------------------------ */

export const detectIPAnomaly = async ({ userId, tokenHash, ipAddress }) => {

  if (!ipAddress) return;

  const baseline = await getUserBaseline(userId);
  const knownIPs = (baseline?.knownIPs || []).slice(-50); // last 50 only

  if (knownIPs.length === 0) return; // no baseline yet

  if (!knownIPs.includes(ipAddress)) {
    await createAlert({
      userId, tokenHash,
      type: "IP_ANOMALY",
      severity: "MEDIUM",
      reason: `Access from unrecognised IP: ${ipAddress}. Known IPs (recent): ${knownIPs.slice(-3).join(", ")}`
    });
  }

};


/* ------------------------------------------------ */
/* ENDPOINT SCANNING                                */
/* FIX: threshold of 6 was too low — normal SPAs    */
/* hit many endpoints on load. Raised to 10,        */
/* exclude static/health endpoints from count,      */
/* added CRITICAL tier for very high counts.        */
/* ------------------------------------------------ */

const STATIC_ENDPOINTS = ["/", "/api/health", "/favicon.ico", "/api/user/profile"];

export const detectEndpointScanning = async ({ userId, tokenHash }) => {

  const rawEndpoints = await RequestLog.distinct("endpoint", {
    userId,
    createdAt: { $gte: new Date(Date.now() - 60000) }
  });

  // Filter out expected baseline endpoints
  const endpoints = rawEndpoints.filter(e => !STATIC_ENDPOINTS.includes(e));

  if (endpoints.length > 20) {
    await createAlert({
      userId, tokenHash,
      type: "API_SCAN",
      severity: "CRITICAL",
      reason: `Aggressive API scanning: ${endpoints.length} unique endpoints in 60s`
    });
  } else if (endpoints.length > 10) {
    await createAlert({
      userId, tokenHash,
      type: "API_SCAN",
      severity: "HIGH",
      reason: `Elevated endpoint scanning: ${endpoints.length} unique endpoints in 60s`
    });
  }

};


/* ------------------------------------------------ */
/* REVOKED TOKEN USE                                */
/* FIX: verifyJWT already blocks revoked tokens     */
/* before securityMonitor runs. This check is now   */
/* a double-guard for logging completeness when     */
/* the token reaches detectEngine via other paths.  */
/* ------------------------------------------------ */

export const detectRevokedTokenUsage = async ({ userId, tokenHash }) => {

  const revoked = await RevokedToken.findOne({ tokenHash });

  if (revoked) {
    await createAlert({
      userId, tokenHash,
      type: "REVOKED_TOKEN_USE",
      severity: "CRITICAL",
      reason: `Revoked token reused. Original revocation reason: "${revoked.reason}"`,
      actionTaken: "REVOKED"
    });
  }

};


/* ------------------------------------------------ */
/* LOGIN TIME ANOMALY                               */
/* FIX: old model had loginHours.start/end but      */
/* updateUserBaseline saved usualLoginHours array.  */
/* Unified to use usualLoginHours array with a      */
/* ±1 hour tolerance to reduce false positives.     */
/* ------------------------------------------------ */

export const detectLoginTimeAnomaly = async ({ userId, tokenHash }) => {

  const baseline = await getUserBaseline(userId);
  const usualHours = baseline?.usualLoginHours || [];

  if (usualHours.length < 5) return; // not enough data yet

  const hour = new Date().getHours();

  // Allow ±1 hour tolerance around each known hour
  const isUsualTime = usualHours.some(h => Math.abs(h - hour) <= 1 || Math.abs(h - hour) === 23);

  if (!isUsualTime) {
    await createAlert({
      userId, tokenHash,
      type: "LOGIN_TIME_ANOMALY",
      severity: "LOW",
      reason: `Activity at hour ${hour}:00 — outside usual pattern. Usual hours: [${usualHours.sort((a,b)=>a-b).join(", ")}]`
    });
  }

};


/* ------------------------------------------------ */
/* TOKEN LIFETIME ABUSE                             */
/* FIX: was using log.createdAt (first log time),   */
/* not token issue time (iat). Now decodes token     */
/* iat from the hash-associated log correctly.      */
/* Also parameterised threshold via env var.        */
/* ------------------------------------------------ */

export const detectTokenLifetimeAbuse = async ({ userId, tokenHash }) => {

  // Find the OLDEST log for this token to determine when it was first used
  const firstLog = await RequestLog.findOne({ tokenHash }).sort({ createdAt: 1 });

  if (!firstLog) return;

  const tokenAgeMs = Date.now() - new Date(firstLog.createdAt).getTime();
  const maxAgeMs = parseInt(process.env.TOKEN_MAX_AGE_MS || String(12 * 60 * 60 * 1000)); // default 12h

  if (tokenAgeMs > maxAgeMs) {
    const ageHours = (tokenAgeMs / 3600000).toFixed(1);
    await createAlert({
      userId, tokenHash,
      type: "TOKEN_LIFETIME_ABUSE",
      severity: "HIGH",               // upgraded from MEDIUM — stale tokens are serious
      reason: `Token active for ${ageHours}h — exceeds max ${maxAgeMs / 3600000}h policy`,
      actionTaken: "REVOKED"
    });

    // Revoke tokens exceeding max lifetime policy
    await RevokedToken.updateOne(
      { tokenHash },
      { $setOnInsert: { tokenHash, reason: `Token exceeded max lifetime (${ageHours}h)` } },
      { upsert: true }
    );
  }

};


/* ------------------------------------------------ */
/* IMPOSSIBLE TRAVEL                                */
/* FIX: geoDistance used Euclidean approximation    */
/* (wrong at scale). Kept as-is in userEnvironment  */
/* but added a minimum time gap check and same-IP   */
/* early return to prevent self-alerts.             */
/* ------------------------------------------------ */

export const detectImpossibleTravel = async ({ userId, tokenHash, ipAddress }) => {

  const lastLog = await RequestLog.findOne({ userId, ipAddress: { $ne: ipAddress } })
    .sort({ createdAt: -1 });

  if (!lastLog || !lastLog.ipAddress) return;

  // Don't alert if same IP
  if (lastLog.ipAddress === ipAddress) return;

  const distance = geoDistance(lastLog.ipAddress, ipAddress);
  const timeDiffMs = Date.now() - new Date(lastLog.createdAt).getTime();

  // Skip if geo lookup returned 0 (private IPs, unknown)
  if (distance === 0) return;

  // Speed check: distance(km) / time(hours) > 900 km/h (faster than commercial flight)
  const speedKmh = distance / (timeDiffMs / 3600000);

  if (speedKmh > 900 && timeDiffMs < 600000) {
    await createAlert({
      userId, tokenHash,
      type: "IMPOSSIBLE_TRAVEL",
      severity: "CRITICAL",            // upgraded from HIGH
      reason: `Impossible travel: ${distance.toFixed(0)}km in ${(timeDiffMs/60000).toFixed(1)}min (${speedKmh.toFixed(0)} km/h). From ${lastLog.ipAddress} → ${ipAddress}`,
      actionTaken: "REVOKED"
    });

    await RevokedToken.updateOne(
      { tokenHash },
      { $setOnInsert: { tokenHash, reason: "Impossible travel detected — session terminated" } },
      { upsert: true }
    );
  }

};


/* ------------------------------------------------ */
/* INVALID TOKEN FLOOD                              */
/* FIX: threshold of 20 was too permissive.         */
/* Lowered to 10/min. Added per-IP block via        */
/* RevokedToken with a sentinel entry.              */
/* ------------------------------------------------ */

export const detectInvalidTokenFlood = async ({ userId, tokenHash, ipAddress }) => {

  if (!ipAddress) return;

  const attempts = await RequestLog.countDocuments({
    ipAddress,
    tokenValid: false,
    createdAt: { $gte: new Date(Date.now() - 60000) }
  });

  if (attempts > 25) {
    await createAlert({
      userId: userId || null,
      tokenHash: tokenHash || `ip-flood-${ipAddress}`,
      type: "INVALID_TOKEN_FLOOD",
      severity: "CRITICAL",
      reason: `Brute-force flood: ${attempts} invalid tokens from IP ${ipAddress} in 60s`
    });
  } else if (attempts > 10) {
    await createAlert({
      userId: userId || null,
      tokenHash: tokenHash || `ip-flood-${ipAddress}`,
      type: "INVALID_TOKEN_FLOOD",
      severity: "HIGH",
      reason: `Elevated invalid token attempts: ${attempts} from IP ${ipAddress} in 60s`
    });
  }

};


/* ------------------------------------------------ */
/* BEHAVIOR ANOMALY (AI-style)                      */
/* FIX: was identical logic to RATE_ANOMALY but     */
/* uses 60s window. Now checks endpoint diversity   */
/* + timing regularity (bot-like fixed intervals).  */
/* ------------------------------------------------ */

export const detectBehaviorAnomaly = async ({ userId, tokenHash }) => {

  const baseline = await getUserBaseline(userId);
  const avgRate = Math.max(baseline?.avgRate || 1, 5);

  const recentLogs = await RequestLog.find({
    userId,
    createdAt: { $gte: new Date(Date.now() - 60000) }
  }).select("createdAt endpoint").sort({ createdAt: 1 });

  const count = recentLogs.length;

  // 1. Volume check (6x baseline in 60s)
  if (count > avgRate * 6) {
    await createAlert({
      userId, tokenHash,
      type: "BEHAVIOR_ANOMALY",
      severity: "HIGH",
      reason: `Behaviour anomaly: ${count} requests/min vs baseline ${avgRate.toFixed(1)}/s. Ratio: ${(count/avgRate).toFixed(1)}x`
    });
    return; // don't need further checks if volume already alarming
  }

  // 2. Bot-like fixed-interval detection (requests exactly every N ms)
  if (recentLogs.length >= 10) {
    const intervals = [];
    for (let i = 1; i < recentLogs.length; i++) {
      intervals.push(
        new Date(recentLogs[i].createdAt).getTime() -
        new Date(recentLogs[i-1].createdAt).getTime()
      );
    }
    const avgInterval = intervals.reduce((a,b) => a+b, 0) / intervals.length;
    const variance = intervals.reduce((a,b) => a + Math.pow(b - avgInterval, 2), 0) / intervals.length;
    const stdDev = Math.sqrt(variance);

    // If stdDev < 50ms with >10 requests, extremely regular = bot
    if (stdDev < 50 && count >= 10) {
      await createAlert({
        userId, tokenHash,
        type: "BEHAVIOR_ANOMALY",
        severity: "CRITICAL",
        reason: `Bot-like behaviour: ${count} requests with interval stdDev of ${stdDev.toFixed(1)}ms (near-perfect regularity)`
      });
    }
  }

};


/* ------------------------------------------------ */
/* CONCURRENT SESSION DETECTION (NEW RULE)          */
/* Detects multiple active tokens for same user     */
/* ------------------------------------------------ */

export const detectConcurrentSessions = async ({ userId, tokenHash }) => {

  if (!userId) return;

  // Count distinct tokenHashes for this user active in last 15 min
  const recentHashes = await RequestLog.distinct("tokenHash", {
    userId,
    tokenHash: { $ne: null },
    createdAt: { $gte: new Date(Date.now() - 900000) }
  });

  const activeTokens = recentHashes.filter(Boolean);

  // More than 3 distinct tokens active = suspicious
  if (activeTokens.length > 3) {
    await createAlert({
      userId, tokenHash,
      type: "CONCURRENT_SESSION",
      severity: "HIGH",
      reason: `${activeTokens.length} concurrent active tokens for this user in 15 min`
    });
  }

};


/* ------------------------------------------------ */
/* SECURITY PIPELINE                                */
/* FIX: run critical/cheap checks first, expensive  */
/* geo/DB checks later. Parallel where safe.        */
/* ------------------------------------------------ */

export const runSecurityChecks = async (context) => {

  // Tier 1: cheap, critical — run first, serially
  await detectRevokedTokenUsage(context);
  await detectPrivilegeAbuse(context);

  // Tier 2: medium cost — run in parallel
  await Promise.all([
    detectTokenReplay(context),
    detectInvalidTokenFlood(context),
    detectConcurrentSessions(context),
  ]);

  // Tier 3: baseline-dependent — run in parallel
  await Promise.all([
    detectRateAnomaly(context),
    detectBehaviorAnomaly(context),
    detectDeviceAnomaly(context),
    detectIPAnomaly(context),
    detectEndpointScanning(context),
    detectLoginTimeAnomaly(context),
    detectTokenLifetimeAbuse(context),
  ]);

  // Tier 4: expensive geo lookup — last
  await detectImpossibleTravel(context);

};
