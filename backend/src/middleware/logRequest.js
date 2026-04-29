import RequestLog from "../models/RequestLog.js";
import { normalizeIp } from "../utils/ipUtils.js";
import {
  detectTokenReplay,
  detectRateAbuse,
  detectPrivilegeAbuse,
} from "../utils/detectionEngine.js";

export const logRequest = async (req, res, next) => {
  const start = Date.now();

  res.on("finish", async () => {
    try {
      const ipAddress = normalizeIp(
        req.headers["x-forwarded-for"]?.split(",")[0] ||
          req.socket.remoteAddress ||
          "unknown"
      );

      const userAgent = req.headers["user-agent"] || "unknown";

      await RequestLog.create({
        userId: req.user?.userId || null,
        tokenHash: req.tokenHash || null,
        ipAddress,
        userAgent,
        endpoint: req.originalUrl,
        method: req.method,
        statusCode: res.statusCode,
        responseTimeMs: Date.now() - start,
      });

      // ✅ Run Detection Rules after logging
      if (req.user?.userId && req.tokenHash) {
        await detectTokenReplay({
          userId: req.user.userId,
          tokenHash: req.tokenHash,
          ipAddress,
        });

        await detectRateAbuse({
          userId: req.user.userId,
          tokenHash: req.tokenHash,
        });

        await detectPrivilegeAbuse({
          userId: req.user.userId,
          tokenHash: req.tokenHash,
          endpoint: req.originalUrl,
          role: req.user.role,
        });
      }
    } catch (err) {
      console.error("❌ Logging/Detection failed:", err.message);
    }
  });

  next();
};
