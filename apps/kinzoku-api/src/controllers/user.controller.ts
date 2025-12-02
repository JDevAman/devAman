import { Request, Response } from "express";
import { userService } from "../services/user.service";
import { schemas } from "@kinzoku/shared/generated/zod-schemas";
import { userRepository } from "../repositories/user.repository";
import config from "../config";

const ACCESS_MS = 15 * 60 * 1000; // or compute via ms lib if you want from config.accessTokenExpiresIn
const REFRESH_MS = config.refreshTokenExpiresDays * 24 * 60 * 60 * 1000;

export const signUp = async (req: Request, res: Response) => {
  try {
    const validation = schemas.SignupInput.safeParse(req.body);
    if (!validation.success) {
      return res.status(422).json({ message: "Invalid input data" });
    }

    // ✅ FIX 1: SignUp now returns both tokens (User is auto-logged in)
    const { user, accessToken, refreshToken } = await userService.signUp(
      validation.data
    );

    res.cookie(config.cookie.accessCookieName, accessToken, {
      httpOnly: true,
      secure: config.cookie.secure,
      sameSite: config.cookie.sameSite,
      path: "/",
      maxAge: ACCESS_MS,
    });

    res.cookie(config.cookie.refreshCookieName, refreshToken, {
      httpOnly: true,
      secure: config.cookie.secure,
      sameSite: config.cookie.sameSite,
      path: "/",
      maxAge: REFRESH_MS,
    });

    return res.status(201).json({
      message: "User successfully created",
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        avatar: user.avatar,
      },
    });
  } catch (error: any) {
    const status = error.message === "User already exists!" ? 409 : 500;
    return res.status(status).json({ message: error.message });
  }
};

export const signIn = async (req: Request, res: Response) => {
  try {
    const validation = schemas.SigninInput.safeParse(req.body);
    if (!validation.success)
      return res.status(422).json({ message: "Invalid input" });

    const { user, accessToken, refreshToken } = await userService.signIn(
      validation.data
    );

    res.cookie(config.cookie.accessCookieName, accessToken, {
      httpOnly: true,
      secure: config.cookie.secure,
      sameSite: config.cookie.sameSite,
      path: "/",
      maxAge: ACCESS_MS,
    });

    res.cookie(config.cookie.refreshCookieName, refreshToken, {
      httpOnly: true,
      secure: config.cookie.secure,
      sameSite: config.cookie.sameSite,
      path: "/",
      maxAge: REFRESH_MS,
    });

    return res.status(200).json({
      message: "Logged in",
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (error: any) {
    return res.status(401).json({ message: error.message });
  }
};

export const refresh = async (req: Request, res: Response) => {
  const incomingRefreshToken = req.cookies.refresh_token;

  if (!incomingRefreshToken) {
    return res.status(401).json({ message: "Refresh Token Missing" });
  }

  try {
    const { accessToken } =
      await userService.refreshAccessToken(incomingRefreshToken);
    // Send new Access Token
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: ACCESS_MS,
      path: "/",
    });

    return res.json({ message: "Access token refreshed" });
  } catch (error: any) {
    // If refresh fails, clear everything so user is forced to login
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken", { path: "/api/v1/auth" });
    return res
      .status(403)
      .json({ message: "Invalid Refresh Token, please login again" });
  }
};

export const updateProfile = async (req: Request, res: Response) => {
  try {
    const validation = schemas.UpdateProfileInput.safeParse(req.body);
    if (!validation.success) {
      return res.status(422).json({ message: "Invalid profile data" });
    }

    // @ts-ignore
    const currentUser = req.user;

    const result = await userService.updateProfile(
      currentUser.id,
      validation.data
    );

    // ✅ FIX 4: Only update Access Token (Refresh token stays same)
    // Note: UserService needs to return just the token here
    res.cookie(config.cookie.accessCookieName, result.token, {
      httpOnly: true,
      secure: config.cookie.secure,
      sameSite: config.cookie.sameSite,
      path: "/",
      maxAge: ACCESS_MS,
    });

    return res.status(200).json({ message: "User profile updated" });
  } catch (error: any) {
    return res.status(500).json({ message: error.message });
  }
};

export const getMe = async (req: Request, res: Response) => {
  // @ts-ignore
  const userFromAuth = req.user;
  if (!userFromAuth) return res.status(401).json({ message: "Not logged in" });

  const user = await userRepository.findById(userFromAuth.id);

  if (!user) {
    return res.status(404).json({ message: "User no longer exists" });
  }

  return res.status(200).json({ user });
};

export const logout = async (req: Request, res: Response) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      // Try to remove from DB
      await userService.logout(refreshToken);
    }

    // Success response
    return res.status(200).json({ message: "Logged out successfully" });
  } catch (error: any) {
    console.error("Logout Error:", error);
    // Even if DB fails, we return 200 so the frontend feels "logged out"
    return res
      .status(200)
      .json({ message: "Logged out (Server cleanup failed)" });
  } finally {
    // ✅ CRITICAL: Always clear cookies, even if DB explodes
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken", { path: "/api/v1/auth" });
  }
};

export const bulkSearch = async (req: Request, res: Response) => {
  try {
    const filter = req.query.filter as string;
    if (!filter)
      return res.status(400).json({ message: "Missing filter param" });

    const users = await userService.bulkSearch(filter);
    return res.status(200).json({ users });
  } catch (error) {
    return res.status(500).json({ message: "Internal Server Error" });
  }
};
