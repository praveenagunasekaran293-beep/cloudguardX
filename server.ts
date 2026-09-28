import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import { initDatabase } from "./server/db.js";
import { apiRouter } from "./server/routes.js";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3000;

  // Initialize SQLite schema and initial synthetic data
  await initDatabase();
  console.log("[CyberSentinel X] SQLite database initialized successfully.");

  app.use(express.json());

  // Mount API endpoints
  app.use("/api", apiRouter);

  // Health check
  app.get("/api/health", (_req, res) => {
    res.json({
      status: "operational",
      platform: "CyberSentinel X SOC Platform",
      mode: "Synthetic Defensive Simulation",
      timestamp: new Date().toISOString(),
    });
  });

  const isProduction = process.env.NODE_ENV === "production";

  if (!isProduction) {
    // Mount Vite middleware in development mode
    const { createServer } = await import("vite");
    const vite = await createServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
    console.log("[CyberSentinel X] Vite dev middleware attached.");
  } else {
    // Production static serving
    const distPath = path.resolve(__dirname, "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.resolve(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[CyberSentinel X] Server running at http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error("[CyberSentinel X] Fatal Server Boot Error:", err);
  process.exit(1);
});
