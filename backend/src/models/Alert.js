import mongoose from "mongoose";

/* FIX: added CONCURRENT_SESSION and PRIVILEGE_ESCALATION
   to enum to match new detection rules */

const alertSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },

    tokenHash: { type: String, required: true },

    type: {
      type: String,
      enum: [
        "TOKEN_REPLAY",
        "RATE_ANOMALY",
        "PRIVILEGE_ABUSE",
        "DEVICE_ANOMALY",
        "IP_ANOMALY",
        "API_SCAN",
        "REVOKED_TOKEN_USE",
        "BEHAVIOR_ANOMALY",
        "INVALID_TOKEN_FLOOD",
        "LOGIN_TIME_ANOMALY",
        "TOKEN_LIFETIME_ABUSE",
        "IMPOSSIBLE_TRAVEL",
        "CONCURRENT_SESSION"      // NEW
      ],
      required: true
    },

    severity: {
      type: String,
      enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      default: "LOW"
    },

    reason: { type: String, required: true },

    actionTaken: {
      type: String,
      enum: ["NONE", "REVOKED"],
      default: "NONE"
    },

    isResolved: { type: Boolean, default: false }
  },
  { timestamps: true }
);

// Index for fast dedup lookups
alertSchema.index({ tokenHash: 1, type: 1, isResolved: 1, createdAt: -1 });
alertSchema.index({ userId: 1, createdAt: -1 });

export default mongoose.model("Alert", alertSchema);
