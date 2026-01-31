import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import crypto from "crypto";
import rateLimit from "express-rate-limit";

const app = express();
app.use(cors({ origin: "http://localhost:8080", credentials: true }));
app.use(cookieParser());
const port = 3000;

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many authentication attempts, please try again later",
  standardHeaders: true,
  legacyHeaders: false,
});

let counter = 0;

const CONFIG = {
  REDIRECT_URI: process.env.REDIRECT_URI,
  AUTH_DOMAIN_PREFIX: process.env.AUTH_DOMAIN_PREFIX,
  COGNITO_USER_POOL_CLIENT_ID: process.env.COGNITO_USER_POOL_CLIENT_ID,
  COGNITO_USER_POOL_CLIENT_SECRET: process.env.COGNITO_USER_POOL_CLIENT_SECRET,
  AWS_REGION: process.env.AWS_REGION,
  COGNITO_USER_POOL_ID: process.env.COGNITO_USER_POOL_ID,
  SECURE_COOKIES: process.env.SECURE_COOKIES === "true",
};

const cognitoIssuer = `https://cognito-idp.${CONFIG.AWS_REGION}.amazonaws.com/${CONFIG.COGNITO_USER_POOL_ID}`;
const jwksUri = `${cognitoIssuer}/.well-known/jwks.json`;

const client = jwksClient({
  jwksUri,
  cache: true,
  cacheMaxAge: 600000,
});

const getKey = (header, callback) => {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err);
    } else {
      const signingKey = key.getPublicKey();
      callback(null, signingKey);
    }
  });
};

const setTokenCookies = (
  res,
  { id_token, access_token, refresh_token, expires_in },
) => {
  res.cookie("id_token", id_token, {
    httpOnly: true,
    secure: CONFIG.SECURE_COOKIES,
    sameSite: "strict",
    maxAge: expires_in * 1000,
  });
  res.cookie("access_token", access_token, {
    httpOnly: true,
    secure: CONFIG.SECURE_COOKIES,
    sameSite: "strict",
    maxAge: expires_in * 1000,
  });
  if (refresh_token) {
    res.cookie("refresh_token", refresh_token, {
      httpOnly: true,
      secure: CONFIG.SECURE_COOKIES,
      sameSite: "strict",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });
  }
};

const refreshTokens = async (refreshToken) => {
  const auth = Buffer.from(
    `${CONFIG.COGNITO_USER_POOL_CLIENT_ID}:${CONFIG.COGNITO_USER_POOL_CLIENT_SECRET}`,
  ).toString("base64");

  const response = await fetch(
    `https://${CONFIG.AUTH_DOMAIN_PREFIX}.auth.${CONFIG.AWS_REGION}.amazoncognito.com/oauth2/token`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${auth}`,
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: CONFIG.COGNITO_USER_POOL_CLIENT_ID,
        refresh_token: refreshToken,
      }),
    },
  );

  if (!response.ok) {
    throw new Error("Token refresh failed");
  }

  return await response.json();
};

const authenticate = async (req, res, next) => {
  const token = req.cookies.access_token;
  const refreshToken = req.cookies.refresh_token;

  if (!token) {
    return res.status(401).send({ error: "Unauthorized" });
  }

  const decoded = jwt.decode(token);
  if (!decoded || !decoded.exp) {
    return res.status(401).send({ error: "Invalid token" });
  }

  const now = Math.floor(Date.now() / 1000);
  const timeUntilExpiry = decoded.exp - now;

  if (timeUntilExpiry < 300) {
    if (!refreshToken) {
      return res.status(401).send({ error: "Token expired" });
    }

    try {
      const data = await refreshTokens(refreshToken);
      setTokenCookies(res, data);
      req.cookies.access_token = data.access_token;
    } catch (err) {
      return res.status(401).send({ error: "Token refresh failed" });
    }
  }

  jwt.verify(
    req.cookies.access_token,
    getKey,
    {
      issuer: cognitoIssuer,
      algorithms: ["RS256"],
    },
    (err, verified) => {
      if (err) {
        return res.status(401).send({ error: "Invalid token" });
      }
      req.user = verified;
      next();
    },
  );
};

app.get("/", authLimiter, async (req, res) => {
  const code = req.query.code;
  const state = req.query.state;
  const storedState = req.cookies.oauth_state;
  const codeVerifier = req.cookies.code_verifier;

  if (!code) {
    return res.send("No code provided");
  }

  if (!state || !storedState || state !== storedState) {
    res.clearCookie("oauth_state");
    res.clearCookie("code_verifier");
    return res.status(403).send("Invalid state parameter");
  }

  if (!codeVerifier) {
    res.clearCookie("oauth_state");
    res.clearCookie("code_verifier");
    return res.status(403).send("Missing code verifier");
  }

  res.clearCookie("oauth_state");
  res.clearCookie("code_verifier");

  const requestParams = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: CONFIG.COGNITO_USER_POOL_CLIENT_ID,
    client_secret: CONFIG.COGNITO_USER_POOL_CLIENT_SECRET,
    redirect_uri: CONFIG.REDIRECT_URI,
    code: code,
    code_verifier: codeVerifier,
  });

  try {
    const response = await fetch(
      `https://${CONFIG.AUTH_DOMAIN_PREFIX}.auth.${CONFIG.AWS_REGION}.amazoncognito.com/oauth2/token`,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: requestParams,
      },
    );

    if (!response.ok) {
      return res.status(401).send("Authentication failed");
    }

    const data = await response.json();

    if (!data.access_token || !data.id_token) {
      return res.status(401).send("Authentication failed");
    }

    setTokenCookies(res, data);
    res.redirect("http://localhost:8080");
  } catch (err) {
    return res.status(500).send("Authentication error");
  }
});

app.get("/login", authLimiter, (_, res) => {
  const state = crypto.randomBytes(32).toString("hex");
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");

  res.cookie("oauth_state", state, {
    httpOnly: true,
    secure: CONFIG.SECURE_COOKIES,
    sameSite: "lax",
    maxAge: 10 * 60 * 1000,
  });

  res.cookie("code_verifier", codeVerifier, {
    httpOnly: true,
    secure: CONFIG.SECURE_COOKIES,
    sameSite: "lax",
    maxAge: 10 * 60 * 1000,
  });

  const cognitoUrl = new URL(
    `https://${CONFIG.AUTH_DOMAIN_PREFIX}.auth.${CONFIG.AWS_REGION}.amazoncognito.com/login`,
  );
  cognitoUrl.searchParams.set("response_type", "code");
  cognitoUrl.searchParams.set("client_id", CONFIG.COGNITO_USER_POOL_CLIENT_ID);
  cognitoUrl.searchParams.set("redirect_uri", CONFIG.REDIRECT_URI);
  cognitoUrl.searchParams.set("scope", "email openid profile");
  cognitoUrl.searchParams.set("state", state);
  cognitoUrl.searchParams.set("code_challenge", codeChallenge);
  cognitoUrl.searchParams.set("code_challenge_method", "S256");
  const loginUrl = cognitoUrl.href;
  res.redirect(loginUrl);
});

app.get("/profile", authenticate, (req, res) => {
  const idToken = req.cookies.id_token;
  const decoded = jwt.decode(idToken);
  res.send({
    username:
      decoded?.name ||
      decoded?.email ||
      decoded?.["cognito:username"] ||
      "Unknown",
    email: decoded?.email,
    sub: req.user.sub,
  });
});

app.get("/protected", authenticate, (_, res) => {
  res.send({ message: "This is protected data" });
});

app.get("/counter", (_, res) => {
  res.send({ counter });
});

app.post("/counter/increment", (_, res) => {
  counter++;
  res.send({ counter, message: "Counter incremented" });
});

const handleLogout = (_, res) => {
  res.clearCookie("id_token");
  res.clearCookie("access_token");
  res.clearCookie("refresh_token");
  res.send({ message: "Logged out" });
};

app.get("/logout", handleLogout);
app.post("/logout", handleLogout);
app.put("/logout", handleLogout);

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
