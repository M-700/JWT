import express from "express";
import cors from "cors";

import authRoutes from "./routes/authRoutes.js";
import dashboardRoutes from "./routes/dashboardRoutes.js";
import analyticsRoutes from "./routes/analyticsRoutes.js";
import userRoutes from "./routes/userRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";

import { securityMonitor } from "./middleware/securityMonitor.js";
import { verifyJWT } from "./middleware/verifyJWT.js";

const app = express();

app.set("trust proxy", true);
app.use(cors());
app.use(express.json());


/* Public routes */
app.use("/api/auth", authRoutes);
app.use("/api/dashboard", dashboardRoutes);
app.use("/api/analytics", analyticsRoutes);

/* Protected routes */
app.use("/api/user", verifyJWT, securityMonitor, userRoutes);
app.use("/api/admin", verifyJWT, securityMonitor, adminRoutes);


app.get("/", (req, res) => {
  res.json({ message: "JWT Abuse Detection Backend Running ✅" });
});

export default app;
