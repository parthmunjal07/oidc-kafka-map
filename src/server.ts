import http from 'node:http';
import path from 'node:path';
import express, { type Request, type Response } from 'express';
import jose from "node-jose"
import { PUBLIC_KEY } from './utils/cert.js';
import authRouter from './auth/auth.routes.js';
import JWT from 'jsonwebtoken'
import type { JWTClaims } from './utils/jwt.js';
import { usersTable } from './db/schema.js';
import { eq } from 'drizzle-orm';
import { db } from './db/index.js';
import 'dotenv/config';

export interface CheckboxData {
    index: number;
    checked: boolean;
}

export interface ErrorData {
    data: CheckboxData;
    message: string;
}

export interface ServerToClientEvents {
    "server:checkbox:status": (checkboxes: (boolean | null)[]) => void;
    "server:checkbox:change": (data: CheckboxData) => void;
    "server:error": (error: ErrorData) => void;
}

export interface ClientToServerEvents {
    "client:checkbox:change": (data: CheckboxData) => void;
}

async function main() {
    const app = express();
    app.use(express.json());

    const server = http.createServer(app);
    const PORT = process.env.PORT || 8181;

    app.get('/health', (req: Request, res: Response) => {
        res.json({ health: true });
    });

    app.use(express.static(path.resolve('./public')));

    // oidc-auth part

    app.get("/.well-known/openid-configuration", (req, res) => {
        const ISSUER = `http://localhost:${PORT}`;
        return res.json({
            issuer: ISSUER,
            authorization_endpoint: `${ISSUER}/o/authenticate`,
            userinfo_endpoint: `${ISSUER}/o/userinfo`,
            jwks_uri: `${ISSUER}/.well-known/jwks.json`,
        });
    });

    app.get("/.well-known/jwks.json", async (_, res) => {
      const key = await jose.JWK.asKey(PUBLIC_KEY, "pem");
      return res.json({ keys: [key.toJSON()] });
    });

    app.use("/o/auth", authRouter)

    app.get("/o/userinfo", async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    res
      .status(401)
      .json({ message: "Missing or invalid Authorization header." });
    return;
  }

  const token = authHeader.slice(7);

  let claims: JWTClaims;
  try {
    claims = JWT.verify(token, PUBLIC_KEY, {
      algorithms: ["RS256"],
    }) as JWTClaims;
  } catch {
    res.status(401).json({ message: "Invalid or expired token." });
    return;
  }

  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, claims.sub))
    .limit(1);

        if (!user) {
          res.status(404).json({ message: "User not found." });
          return;
        }

        res.json({
            sub: user.id,
            email: user.email,
            email_verified: user.emailVerified,
            given_name: user.name,
            name: user.name,
            picture: user.profileImageURL,
        });
    });

    server.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });
}

main().catch(console.error);