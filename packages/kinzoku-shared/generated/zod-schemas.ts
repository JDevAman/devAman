import { makeApi, Zodios, type ZodiosOptions } from "@zodios/core";
import { z } from "zod";

type TokenResponse = {
  /**
   * Short-lived access token (if not using HttpOnly cookie)
   *
   * @example "eyJhbGciOi..."
   */
  accessToken: string;
  /**
   * Long-lived refresh token (if not using HttpOnly cookie)
   *
   * @example "r3fr3sh_..."
   */
  refreshToken: string;
  user?: AuthUser | undefined;
};
type AuthUser = {
  /**
   * @example "9b1deb4d-0000-0000-0000-2f3a"
   */
  id: string;
  /**
   * @example "aman@example.com"
   */
  email: string;
  /**
   * @example "user"
   */
  role: string;
};
type SignUpResponse = {
  message?: /**
   * @example "User created successfully"
   */
  string | undefined;
  user: User;
  tokens?: TokenResponse | undefined;
};
type User = {
  /**
   * @example "9b1deb4d-0000-0000-0000-2f3a"
   */
  id: string;
  /**
   * @example "Aman"
   */
  firstName: string;
  /**
   * @example "Patel"
   */
  lastName: string;
  /**
   * @example "aman@example.com"
   */
  email: string;
  /**
   * @example "user"
   */
  role: string;
  avatar?:
    | /**
     * URL to user avatar
     */
    (string | null)
    | undefined;
};
type SignInResponse = {
  message?: /**
   * @example "Login successful"
   */
  string | undefined;
  user: AuthUser;
  tokens?: TokenResponse | undefined;
};

const SignupInput = z
  .object({
    firstName: z.string(),
    lastName: z.string(),
    email: z.string().email(),
    password: z.string().describe("Client-side plain password (min 8 chars)."),
  })
  .passthrough();
const User: z.ZodType<User> = z
  .object({
    id: z.string().uuid(),
    firstName: z.string(),
    lastName: z.string(),
    email: z.string().email(),
    role: z.string(),
    avatar: z.string().describe("URL to user avatar").nullish(),
  })
  .passthrough();
const AuthUser: z.ZodType<AuthUser> = z
  .object({
    id: z.string().uuid(),
    email: z.string().email(),
    role: z.string(),
  })
  .passthrough();
const TokenResponse: z.ZodType<TokenResponse> = z
  .object({
    accessToken: z
      .string()
      .describe("Short-lived access token (if not using HttpOnly cookie)"),
    refreshToken: z
      .string()
      .describe("Long-lived refresh token (if not using HttpOnly cookie)"),
    user: AuthUser.optional(),
  })
  .passthrough();
const SignUpResponse: z.ZodType<SignUpResponse> = z
  .object({
    message: z.string().optional(),
    user: User,
    tokens: TokenResponse.optional(),
  })
  .passthrough();
const ErrorResponse = z
  .object({
    code: z.string(),
    message: z.string(),
    details: z
      .array(
        z
          .object({ field: z.string(), reason: z.string() })
          .partial()
          .passthrough()
      )
      .describe("Array of field-level errors (optional)"),
  })
  .partial()
  .passthrough();
const SigninInput = z
  .object({
    email: z.string().email(),
    password: z.string().describe("Plain-text password sent over TLS"),
  })
  .passthrough();
const SignInResponse: z.ZodType<SignInResponse> = z
  .object({
    message: z.string().optional(),
    user: AuthUser,
    tokens: TokenResponse.optional(),
  })
  .passthrough();
const UpdateProfileInput = z
  .object({
    firstName: z.string(),
    lastName: z.string(),
    email: z.string().email(),
    avatarUrl: z.string().nullable(),
    avatarRemoved: z.boolean(),
  })
  .partial()
  .passthrough();

export const schemas = {
  SignupInput,
  User,
  AuthUser,
  TokenResponse,
  SignUpResponse,
  ErrorResponse,
  SigninInput,
  SignInResponse,
  UpdateProfileInput,
};

const endpoints = makeApi([
  {
    method: "post",
    path: "/auth/refresh",
    alias: "postAuthrefresh",
    description: `Reads the HttpOnly &#x60;refresh_token&#x60; cookie (Path&#x3D;/api/v1/auth) and, if valid, sets a new &#x60;access_token&#x60; cookie (Path&#x3D;/) in the response.
`,
    requestFormat: "json",
    response: z.object({ message: z.string() }).partial().passthrough(),
    errors: [
      {
        status: 401,
        description: `Refresh token missing or invalid`,
        schema: ErrorResponse,
      },
    ],
  },
  {
    method: "patch",
    path: "/user/profile",
    alias: "patchUserprofile",
    requestFormat: "json",
    parameters: [
      {
        name: "body",
        type: "Body",
        schema: UpdateProfileInput,
      },
    ],
    response: User,
    errors: [
      {
        status: 400,
        description: `Validation error`,
        schema: ErrorResponse,
      },
      {
        status: 401,
        description: `Unauthorized (missing/invalid token)`,
        schema: ErrorResponse,
      },
      {
        status: 403,
        description: `Forbidden (insufficient permissions)`,
        schema: ErrorResponse,
      },
    ],
  },
  {
    method: "post",
    path: "/user/signin",
    alias: "postUsersignin",
    requestFormat: "json",
    parameters: [
      {
        name: "body",
        type: "Body",
        schema: SigninInput,
      },
    ],
    response: SignInResponse,
    errors: [
      {
        status: 401,
        description: `Invalid credentials`,
        schema: ErrorResponse,
      },
    ],
  },
  {
    method: "post",
    path: "/user/signup",
    alias: "postUsersignup",
    requestFormat: "json",
    parameters: [
      {
        name: "body",
        type: "Body",
        schema: SignupInput,
      },
    ],
    response: SignUpResponse,
    errors: [
      {
        status: 409,
        description: `User already exists`,
        schema: ErrorResponse,
      },
    ],
  },
]);

export const api = new Zodios("http://localhost:3000/api/v1", endpoints);

export function createApiClient(baseUrl: string, options?: ZodiosOptions) {
  return new Zodios(baseUrl, endpoints, options);
}
