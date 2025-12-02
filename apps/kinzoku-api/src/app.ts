import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import config from "./config";
import { prisma } from "./db";
import mainRouter from "./routes/main.routes";
import docsRouter from "./docs";

const app = express();

// Middlewares
app.use(express.json());
app.use(
  cors({
    origin: config.frontendURI,
    credentials: true,
  })
);
app.use(cookieParser());

// Routes
app.use("/api/v1", docsRouter);
app.use("/api/v1", mainRouter);

// Error handler
app.use((err, req, res, next) => {
  console.error({ "Error Caught": err.stack || err });
  res
    .status(err.status || 500)
    .json({ error: err.message || "Something went wrong!" });
});

// Start server after DB connection
const startServer = async () => {
  await prisma.$connect();
  app.listen(config.port, () => {
    console.log(`🚀 Server running on port ${config.port}`);
  });
};

startServer();
