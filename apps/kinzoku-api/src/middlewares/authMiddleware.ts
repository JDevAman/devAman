import { verifyAccessToken } from "../utils/tokens";

function authenticate(req, res, next) {
  const token = req.cookies.access_token;

  if (!token) {
    return res.status(401).json({ message: "Access token not found" });
  }

  try {
    const decoded = verifyAccessToken(token);

    if (!decoded?.id) {
      return res.status(401).json({ message: "Invalid token payload" });
    }

    req.user = { id: decoded.id };

    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

export default authenticate;