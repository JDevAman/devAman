import dotenv from "dotenv";
dotenv.config();

const config = {
  jwtsecret: process.env.JWT_SECRET || "secret",
  port: process.env.PORT || 3000,
  pepper: process.env.PEPPER || "hari",
  frontendURI: process.env.FRONTEND_URL,
  accessTokenExpiresIn: process.env.ACCESS_EXPIRES || "15m",
  refreshTokenExpiresDays: Number(process.env.REFRESH_DAYS) || 7,
  cookie: {
    accessCookieName: "access_token", // recommended canonical names
    refreshCookieName: "refresh_token",
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  },
};

export default config;