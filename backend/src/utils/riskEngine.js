import RiskScore from "../models/RiskScore.js";
import RevokedToken from "../models/RevokedToken.js";

/* ------------------------------------------------ */
/* RISK POINTS TABLE                                */
/* FIX: RATE_ABUSE key was never used in original   */
/* (alerts fire as RATE_ANOMALY). All keys now      */
/* match actual alert type strings exactly.         */
/* Added CONCURRENT_SESSION and tiered scoring.     */
/* ------------------------------------------------ */

const RISK_POINTS = {
  TOKEN_REPLAY:        60,   // was 50 — critical attack
  RATE_ANOMALY:        20,   // was RATE_ABUSE (wrong key) — now matches alert type
  PRIVILEGE_ABUSE:     50,   // was 30 — privilege escalation is severe
  DEVICE_ANOMALY:      15,
  IP_ANOMALY:          10,   // was missing — now included
  CONCURRENT_SESSION:  30,   // new rule
  API_SCAN:            20,   // was 15
  REVOKED_TOKEN_USE:   70,   // was 60 — highest single-event score
  BEHAVIOR_ANOMALY:    25,   // was AI_ANOMALY (wrong key)
  IMPOSSIBLE_TRAVEL:   60,   // was 45
  INVALID_TOKEN_FLOOD: 40,   // was 35
  TOKEN_LIFETIME_ABUSE:15,
  LOGIN_TIME_ANOMALY:   5,   // low — informational
};

const calculateLevel = (score) => {
  if (score >= 80) return "CRITICAL";
  if (score >= 50) return "HIGH";    // was 60 — earlier escalation
  if (score >= 25) return "MEDIUM";  // was 30
  return "LOW";
};

export const updateRiskScore = async (userId, tokenHash, alertType) => {

  if (!userId) return; // anonymous flood attempts — no user score to update

  const points = RISK_POINTS[alertType] || 10;

  let risk = await RiskScore.findOne({ userId });

  if (!risk) {
    risk = await RiskScore.create({ userId, score: points });
  } else {
    risk.score = Math.min(risk.score + points, 100);
    risk.lastUpdated = new Date();
  }

  risk.level = calculateLevel(risk.score);
  await risk.save();

  // AUTO-REVOKE at HIGH or CRITICAL
  if (risk.level === "HIGH" || risk.level === "CRITICAL") {
    if (tokenHash) {
      await RevokedToken.updateOne(
        { tokenHash },
        {
          $setOnInsert: {
            tokenHash,
            reason: `Auto-revoked — risk level ${risk.level} (score: ${risk.score})`
          }
        },
        { upsert: true }
      );
    }
    console.warn(`⚠️  User ${userId} reached ${risk.level} risk (${risk.score}pts) — token revoked`);
  }

};

/* ------------------------------------------------ */
/* RISK SCORE DECAY                                 */
/* FIX: decay ran on ALL users every call.          */
/* Now only decays users idle for >30 min, and      */
/* decay rate scales with current level.            */
/* ------------------------------------------------ */

export const decayRiskScores = async () => {

  const thirtyMinsAgo = new Date(Date.now() - 1800000);

  const risks = await RiskScore.find({
    score: { $gt: 0 },
    lastUpdated: { $lt: thirtyMinsAgo }   // only idle users
  });

  for (const risk of risks) {

    // Faster decay from LOW, slower decay from CRITICAL
    const decayAmount = risk.level === "CRITICAL" ? 2
      : risk.level === "HIGH"     ? 3
      : risk.level === "MEDIUM"   ? 5
      : 8; // LOW — recover fast

    risk.score = Math.max(risk.score - decayAmount, 0);
    risk.level = calculateLevel(risk.score);
    risk.lastUpdated = new Date();
    await risk.save();

  }

  if (risks.length > 0) {
    console.log(`🔄 Decayed risk scores for ${risks.length} idle users`);
  }

};
