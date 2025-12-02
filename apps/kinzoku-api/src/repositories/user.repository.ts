import { prisma } from "../db";
import { Prisma, AuthProvider } from "@prisma/client";
import { v4 as uuidv4 } from "uuid";
import { hashToken } from "../utils/tokens";

export class UserRepository {
  async findByEmail(email: string) {
    return await prisma.user.findUnique({
      where: { email: email },
    });
  }

  async findById(id: string) {
    return await prisma.user.findUnique({
      where: { id },
    });
  }

  // Used by Manual Sign Up
  async createUser(data: Prisma.UserCreateInput) {
    return await prisma.user.create({
      data,
    });
  }

  async updateUser(id: string, data: Prisma.UserUpdateInput) {
    return await prisma.user.update({
      where: { id },
      data,
    });
  }

  async searchUsers(filter: string) {
    return await prisma.user.findMany({
      where: {
        OR: [
          { firstName: { contains: filter, mode: "insensitive" } },
          { lastName: { contains: filter, mode: "insensitive" } },
        ],
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
        avatar: true,
      },
    });
  }

  async findOrCreateOAuthUser(data: {
    email: string;
    firstName: string;
    lastName: string;
    avatar?: string;
    provider: AuthProvider; // Ensure you import this from @prisma/client
  }) {
    const existingUser = await this.findByEmail(data.email);
    if (existingUser) return existingUser;

    return await prisma.user.create({
      data: {
        email: data.email,
        firstName: data.firstName,
        lastName: data.lastName,
        avatar: data.avatar,
        // Prisma Enums are strict. Ensure data.provider matches "GOOGLE" or "GITHUB"
        role: "USER", // Default role
        status: "ACTIVE", // Default status
        // Create Account with versioning default
        Account: {
          create: { balance: 0, locked: 0, version: 0 },
        },
      },
    });
  }

  async createRefreshToken(userId: string, rawToken: string, expiresAt: Date) {
    const tokenHash = hashToken(rawToken);
    return await prisma.refreshToken.create({
      data: {
        userId,
        tokenHash,
        expiresAt,
      },
    });
  }

  async findRefreshTokenByRaw(rawToken: string) {
    const tokenHash = hashToken(rawToken);
    return await prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: { user: true },
    });
  }

  // ✅ NEW: Revoke Token (Logout)
  async revokeRefreshTokenById(
    tokenId: string,
    opts?: { replacedById?: string }
  ) {
    return prisma.refreshToken.update({
      where: { id: tokenId },
      data: {
        revoked: true,
      },
    });
  }

  // Revoke all refresh tokens for a user (logout everywhere)
  async revokeAllRefreshTokensForUser(userId: string) {
    return prisma.refreshToken.updateMany({
      where: { userId, revoked: false },
      data: { revoked: true },
    });
  }

  async rotateRefreshToken(
    oldRawToken: string,
    userId: string,
    newExpiresAt: Date
  ) {
    const oldHash = hashToken(oldRawToken);

    return await prisma.$transaction(async (tx) => {
      const oldRecord = await tx.refreshToken.findUnique({
        where: { tokenHash: oldHash },
      });

      if (!oldRecord) {
        throw new Error("Invalid refresh token");
      }

      if (oldRecord.revoked) {
        await tx.refreshToken.updateMany({
          where: { userId },
          data: { revoked: true },
        });
        throw new Error("Refresh token reuse detected");
      }

      if (oldRecord.expiresAt < new Date()) {
        await tx.refreshToken.update({
          where: { id: oldRecord.id },
          data: { revoked: true },
        });
        throw new Error("Refresh token expired");
      }

      const newRaw = uuidv4();
      const newHash = hashToken(newRaw);

      const newRecord = await tx.refreshToken.create({
        data: {
          userId,
          tokenHash: newHash,
          expiresAt: newExpiresAt,
        },
      });

      // revoke old and point to new
      await tx.refreshToken.update({
        where: { id: oldRecord.id },
        data: { revoked: true },
      });

      return { newRawToken: newRaw, newRecord };
    });
  }
}

export const userRepository = new UserRepository();
