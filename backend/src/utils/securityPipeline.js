import { runSecurityChecks } from "./detectionEngine.js";
import {
  updateUserBaseline,
  adaptUserBehavior
} from "./userBehavior.js";
import RiskScore from "../models/RiskScore.js";


export const processSecurityEvent = async (context) => {

  // 1. Run detection rules (tiered parallel execution)
  await runSecurityChecks(context);

  // 2. Determine current risk level before adapting behavior
  // FIX: original always adapted even after critical alert
  // Now: only adapt if user is LOW/MEDIUM risk — don't learn attacker patterns
  if (context.userId) {
    const riskDoc = await RiskScore.findOne({ userId: context.userId });
    const riskLevel = riskDoc?.level || "LOW";

    if (riskLevel === "LOW" || riskLevel === "MEDIUM") {
      await adaptUserBehavior(context);
    } else {
      console.log(`⛔ Skipping behavior adaptation for ${context.userId} — risk level: ${riskLevel}`);
    }
  }

  // 3. Refresh baseline from logs (async, non-blocking)
  if (context.userId) {
    // Fire-and-forget baseline update — don't block the response
    updateUserBaseline(context.userId).catch(err =>
      console.error("Baseline update error:", err.message)
    );
  }

};
