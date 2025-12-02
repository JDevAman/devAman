import path from "path";
import fs from "fs";
import yaml from "yaml";
import { Router } from "express";
import swaggerUi from "swagger-ui-express";

const router = Router();

// Resolve path robustly so it works in dev (ts-node) and production (compiled to dist)
const openapiPath = path.resolve(
  __dirname,
  "..", // from src -> package root or adjust if different structure
  "..",
  "..",
  "packages",
  "kinzoku-shared",
  "openapi.yaml"
);

// Fallback: if openapi not found, throw a clear error
if (!fs.existsSync(openapiPath)) {
  console.error(`openapi.yaml not found at ${openapiPath}. Verify monorepo path.`);
}

// Read and parse YAML once on startup (choose to re-read in dev if you prefer hot reload)
const raw = fs.readFileSync(openapiPath, "utf8");
const openapiDoc = yaml.parse(raw);

// Expose JSON and YAML (optional)
router.get("/openapi.json", (_, res) => {
  res.json(openapiDoc);
});
router.get("/openapi.yaml", (_, res) => {
  res.type("text/yaml").send(raw);
});

// Swagger UI
router.use("/docs", swaggerUi.serve, swaggerUi.setup(openapiDoc, { explorer: true }));

export default router;
