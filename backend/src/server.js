import dotenv from "dotenv";
dotenv.config();

import app from "./app.js";
import { connectDB } from "./config/db.js";

const PORT = process.env.PORT || 5000;

connectDB();

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});

import cron from "node-cron";
import { decayRiskScores } from "./utils/riskEngine.js";

cron.schedule("0 * * * *", async () => {

  console.log("Running risk score decay...");

  await decayRiskScores();

});