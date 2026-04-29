import RequestLog from "../models/RequestLog.js";
import { normalizeIp } from "../utils/ipUtils.js";
import { processSecurityEvent } from "../utils/securityPipeline.js";

export const securityMonitor = async (req, res, next) => {

  // FIX: call next() immediately — do NOT await detection before responding.
  // Detection runs asynchronously after response is sent.
  // This prevents detection latency from affecting API response times.
  next();

  // Run detection after response is handed off
  setImmediate(async () => {
    try {
      const start = Date.now();

      const context = {
        userId:     req.user?.id,
        tokenHash:  req.tokenHash,
        ipAddress:  normalizeIp(req.ip || req.connection?.remoteAddress),
        userAgent:  req.headers["user-agent"],
        endpoint:   req.path,           // FIX: was req.originalUrl (includes query strings)
        method:     req.method,
        role:       req.user?.role,
        tokenValid: req.tokenValid ?? true,
        timestamp:  new Date()
      };

      // Store request log
      await RequestLog.create(context);

      // Run detection pipeline
      await processSecurityEvent(context);

      const elapsed = Date.now() - start;
      if (elapsed > 500) {
        console.warn(`⚠️  Slow detection: ${elapsed}ms for ${context.endpoint}`);
      } else {
        console.log(`⏱ Detection: ${elapsed}ms [${context.method} ${context.endpoint}]`);
      }

    } catch (err) {
      console.error("❌ Security monitor error:", err.message);
    }
  });

};
