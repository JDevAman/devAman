import { Request, Response } from "express";
import { signjwt } from "../utils/tokens";
import config from "../config";

// ✅ This is the ONLY function you need now.
// Passport handles the "Redirect" and "Exchange Code" logic automatically.
export const oauthCallback = (req: Request, res: Response) => {
  // 1. Passport attaches the DB user object to req.user
  const user = req.user as any;

  if (!user) {
    return res.status(401).json({ message: "Authentication failed" });
  }

  // 2. Generate JWT
  const token = signjwt({
    id: user.id,
    email: user.userName,
    firstName: user.firstName,
    lastName: user.lastName,
    avatar: user.avatar,
  });

  // 3. Set Access Token
  res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: 24 * 60 * 60 * 1000,
  });

  //4. Set Refresh Token
  

  // 4. Send the Popup Closer Script
  res.send(`
    <html>
      <body>
        <script>
          window.opener.postMessage({ success: true }, "${config.frontendURI}");
          window.close();
        </script>
      </body>
    </html>
  `);
};