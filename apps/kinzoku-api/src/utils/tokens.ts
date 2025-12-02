import jwt from "jsonwebtoken";
import config from "../config";
import crypto from "crypto";

export type AccessTokenPayload = { id: string };

function hashToken(token: String) {
  return crypto.createHash("SHA256").update(token).digest("hex");
}

function signAccessToken(payload: AccessTokenPayload) {
  return jwt.sign(payload, config.jwtsecret, {
    expiresIn: config.accessTokenExpiresIn,
  });
}

function verifyAccessToken(token: AccessTokenPayload) {
  try {
    return jwt.verify(token, config.jwtsecret) as AccessTokenPayload;
  } catch (err) {
    return null;
  }
}

export { signAccessToken, verifyAccessToken, hashToken };
