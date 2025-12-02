import argon2 from "argon2";
import config from "../config";
import { v4 as uuidv4 } from "uuid";
import { userRepository } from "../repositories/user.repository";
import { signAccessToken } from "../utils/tokens";
import { SignupInput, SigninInput } from "@kinzoku/shared";

export class UserService {
  async signUp(payload: SignupInput) {
    const { firstName, lastName, email, password } = payload;

    // 1. Check existence
    const existingUser = await userRepository.findByEmail(email);
    if (existingUser) {
      throw new Error("User already exists!");
    }

    // 2. Hash Password
    const hashedPassword = await argon2.hash(password + config.pepper);

    // 3. Create User (Repo handles the atomic Account creation)
    const newUser = await userRepository.createUser({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      Account: {
        create: { balance: 0 },
      },
    });

    // 4. Generate Token
    const accessToken = signAccessToken({
      id: newUser.id,
    });

    // 3. Generate Refresh Token
    const refreshToken = uuidv4();
    const refreshExpiresAt = new Date(
      Date.now() + config.refreshTokenExpiresDays * 24 * 60 * 60 * 1000
    );

    // 4. Store Refresh Token
    await userRepository.createRefreshToken(
      newUser.id,
      refreshToken,
      refreshExpiresAt
    );

    // Return EVERYTHING
    return { user: newUser, accessToken, refreshToken };
  }

  async signIn(payload: SigninInput) {
    const { email, password } = payload;

    const user = await userRepository.findByEmail(email);
    if (!user || !user.password) {
      throw new Error("Invalid credentials");
    }

    // ✅ 1. SECURITY CHECK: Is user Banned?
    if (user.status !== "ACTIVE") {
      throw new Error(`Account is ${user.status}. Contact support.`);
    }

    const isValid = await argon2.verify(
      user.password,
      password + config.pepper
    );
    if (!isValid) throw new Error("Incorrect password");

    // ✅ 2. Generate Access Token (JWT) - Short Lived (15m)
    const accessToken = signAccessToken({ id: user.id });

    // ✅ 3. Generate Refresh Token (UUID) - Long Lived (7d)
    const refreshToken = uuidv4();
    const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 Days

    // ✅ 4. Store Refresh Token in DB
    await userRepository.createRefreshToken(
      user.id,
      refreshToken,
      refreshExpiresAt
    );

    return { user, accessToken, refreshToken };
  }

  async refreshAccessToken(incomingRefreshToken: string) {
    const existing =
      await userRepository.findRefreshTokenByRaw(incomingRefreshToken);
    if (!existing) {
      throw new Error("Invalid refresh token");
    }

    if (existing.user.status !== "ACTIVE") {
      await userRepository.revokeAllRefreshTokensForUser(existing.user.id);
      throw new Error("User not active");
    }

    const newExpires = new Date(
      Date.now() + config.refreshTokenExpiresDays * 24 * 60 * 60 * 1000
    );

    const { newRawToken } = await userRepository.rotateRefreshToken(
      incomingRefreshToken,
      existing.user.id,
      newExpires
    );

    // create new access token (JWT)
    const accessToken = signAccessToken({ id: existing.user.id });
    return {
      accessToken,
      refreshToken: newRawToken,
      user: existing.user,
    };
  }

  async logout(refreshToken: string) {
    if (!refreshToken) return;
    await userRepository.deleteRefreshToken(refreshToken);
  }

  async updateProfile(userId: string, payload: updateUserSchema) {
    const { firstName, lastName, email, password } = payload;
    const updateData: any = {};

    // Logic: Check if new email is taken
    if (email && email !== currentUserEmail) {
      const existing = await userRepository.findByEmail(email);
      if (existing) throw new Error("Email already in use");
      updateData.userName = email;
    }

    if (firstName) updateData.firstName = firstName;
    if (lastName) updateData.lastName = lastName;
    if (password) {
      updateData.password = await argon2.hash(password + config.pepper);
    }

    const updatedUser = await userRepository.updateUser(userId, updateData);

    // Re-issue token because details changed
    const token = signAccessToken({
      id: updatedUser.id,
    });

    return { token };
  }

  async bulkSearch(filter: string) {
    return await userRepository.searchUsers(filter);
  }
}

export const userService = new UserService();
