import jwt from "jsonwebtoken";
import crypto from "crypto";
import RevokedToken from "../models/RevokedToken.js";
import RequestLog from "../models/RequestLog.js";
import { normalizeIp } from "../utils/ipUtils.js";

export const verifyJWT = async (req, res, next) => {
  try {
    const auth = req.headers.authorization;

    if (!auth || !auth.startsWith("Bearer ")) {
      return res.status(401).json({ message: "No token provided" });
    }

    const token = auth.split(" ")[1];
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    // Check revocation list
    const revoked = await RevokedToken.findOne({ tokenHash });
    if (revoked) {
      // FIX: log the rejected attempt with tokenValid=false for flood detection
      await RequestLog.create({
        ipAddress: normalizeIp(req.ip),
        userAgent: req.headers["user-agent"],
        endpoint: req.path,
        method: req.method,
        tokenHash,
        tokenValid: false
      }).catch(() => {}); // non-blocking, don't fail the response

      return res.status(401).json({ message: "Token revoked. Please login again." });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user      = { id: decoded.userId, role: decoded.role };
    req.token     = token;
    req.tokenHash = tokenHash;
    req.tokenValid = true;

    next();
  } catch (err) {

    // FIX: log failed/invalid token attempts for INVALID_TOKEN_FLOOD detection
    const rawToken = req.headers.authorization?.split(" ")[1] || "";
    const tokenHash = rawToken
      ? crypto.createHash("sha256").update(rawToken).digest("hex")
      : null;

    await RequestLog.create({
      ipAddress: normalizeIp(req.ip),
      userAgent: req.headers["user-agent"],
      endpoint: req.path,
      method: req.method,
      tokenHash,
      tokenValid: false
    }).catch(() => {});

    return res.status(401).json({ message: "Invalid or expired token" });
  }
};
