import crypto from "crypto";
import express, { Request, Response } from "express";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import axios from "axios";
import querystring from "querystring";
import session from "express-session";
import basicAuth from "basic-auth";

// TODO: code verifier in the session, not the state
// TODO: change redirect url

const app = express();

// Basic auth middleware for API connector
const authenticateForApiConnector = (
  req: Request,
  res: Response,
  next: Function
) => {
  const user = basicAuth(req);
  const expectedUsername = "sorina";
  const expectedPassword = "Sorina123";

  if (
    !user ||
    user.name !== expectedUsername ||
    user.pass !== expectedPassword
  ) {
    res.set("WWW-Authenticate", 'Basic realm="example"');
    return res.status(401).send("Authentication required.");
  }

  next(); // Proceed to the next middleware or route handler
};

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(
  session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }, // Set to true if using HTTPS
  })
);

// Utility functions
function base64URLEncode(str: Buffer): string {
  return str
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64URLDecode(str: string): string {
  // Replace URL-safe characters back to their base64 original form
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  // Pad with '=' to make the string length a multiple of 4
  while (str.length % 4 !== 0) {
    str += "=";
  }
  return Buffer.from(str, "base64").toString();
}

function sha256(buffer: Buffer): Buffer {
  return crypto.createHash("sha256").update(buffer).digest();
}

function generateCodeVerifier(): string {
  return base64URLEncode(crypto.randomBytes(32));
}

async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  return base64URLEncode(sha256(Buffer.from(codeVerifier)));
}

// Configuration variables
const tenantName = "kineticloudb2c";
// const policy = "B2C_1_POC_Sorina";

const policy = "B2C_1_SignUPSignInTest";
const clientId = "c7ff1498-dbac-4aed-bea4-9ffd9c98570d";
const redirectUri = "https://2be6-84-125-125-57.ngrok-free.app/auth-response";
const tenantId = "902b0036-8178-4e76-87f6-febcc72f2570";
const email = "john@smth.com";
const tokenScope = "openid profile";

// Route to show login link
app.get("/", (req: Request, res: Response) => {
  res.send('<a href="/login">Log in or sign up with Azure B2C</a>');
});

// Login route
app.get("/login", async (req: Request, res: Response) => {
  const codeVerifier = generateCodeVerifier();
  console.log("issued:", codeVerifier);
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const codeChallengeMethod = "S256";

  req.session.codeVerifier = codeVerifier; // Store codeVerifier in session for later use
  // todo remove storing code verifier in state param when deploying app, keep it in the session
  const persistedState = base64URLEncode(
    Buffer.from(JSON.stringify({ codeVerifier }))
  );

  const encodedEmail = encodeURIComponent(email);
  const encodedTokenScope = encodeURIComponent(tokenScope);

  const b2cSignUpSignInUrl = `https://${tenantName}.b2clogin.com/${tenantName}.onmicrosoft.com/${policy}/oauth2/v2.0/authorize?client_id=${clientId}&response_type=code&redirect_uri=${redirectUri}&response_mode=form_post&scope=${encodedTokenScope}&state=${persistedState}&code_challenge=${codeChallenge}&code_challenge_method=${codeChallengeMethod}&login_hint=${encodedEmail}&prompt=login&local=signup&option=signup`;

  res.redirect(b2cSignUpSignInUrl);
});

// API connector - pre-fill user role
app.post("/pre-fill-user-role", authenticateForApiConnector, (req, res) => {
  try {
    // Extract the email from the request body
    const email = req.body.email;

    if (!email) {
      return res.status(400).json({ error: "Email is missing in the request" });
    }

    console.log("Email:", email);
    // TODO since email is unique, call backend to resolve role, currently hardcoding role

    const role = "student";

    // Return the response with the role set in the custom attribute
    res.json({
      version: "1.0.0",
      action: "Continue",
      extension_fb13cfd083a04d37aec60d86bae18705_AppUserRole: role, // Pre-fill user role
    });
  } catch (error: any) {
    res.status(500).send("Failed to prefill role.");
  }
});

// Token verification route
app.all("/auth-response", async (req: Request, res: Response) => {
  // todo get the code verifier from req.session.state and remove code getting it from url param

  const decodedState = base64URLDecode(
    req.body.state || (req.query.state as string)
  );
  const { codeVerifier } = JSON.parse(decodedState);
  console.log(`retrieved:`, codeVerifier);

  const code =
    req.method === "POST" ? req.body.code : (req.query.code as string);

  if (!code) {
    return res.status(400).send("Authorization code is missing");
  }

  try {
    const tokenResponse = await axios.post(
      `https://${tenantName}.b2clogin.com/${tenantName}.onmicrosoft.com/${policy}/oauth2/v2.0/token`,
      querystring.stringify({
        client_id: clientId,
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
        scope: "openid profile",
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    console.log("Token response:", tokenResponse.data); // Log the full token response
    const idToken = tokenResponse.data.id_token;
    const decodedToken = jwt.decode(idToken, { complete: true });
    console.log("Decoded Token:", JSON.stringify(decodedToken, null, 2));

    if (!idToken) {
      return res.status(400).send("ID token is missing");
    }

    // Verify the token dynamically
    jwt.verify(
      idToken,
      getKey,
      {
        audience: clientId,
        issuer: `https://${tenantName}.b2clogin.com/${tenantId}/v2.0/`,
      },
      (err: any, decoded: any) => {
        if (err) {
          return res.status(401).send("Token validation failed");
        }

        console.log("Token is valid", decoded);
        const userAttributes = {
          userId: decoded.oid,
          userEmail: decoded.emails ? decoded.emails[0] : null,
          userRole: decoded["extension_AppUserRole"],
        };

        res.send(`
        <h1>Authentication successful!</h1>
       <p><strong>State param:</strong> ${decodedState}</p>
        <p><strong>User role:</strong> ${userAttributes.userRole}</p>
        <p><strong>ID token:</strong> ${idToken}</p>
      `);
      }
    );
  } catch (error: any) {
    console.error(
      "Error exchanging code for token:",
      error.response ? error.response.data : error.message
    );
    res.status(500).send("Error exchanging code for token");
  }
});

// JWKS client
function getKey(header: any, callback: any) {
  const jwksUri = `https://${tenantName}.b2clogin.com/${tenantName}.onmicrosoft.com/${policy}/discovery/v2.0/keys&option=signup`;

  const client = jwksClient({
    jwksUri,
  });

  client.getSigningKey(header.kid, (err: any, key: any) => {
    if (err) {
      console.error("Error fetching signing key:", err.message);
      return callback(err);
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    console.log("Signing Key:", signingKey);
    callback(null, signingKey);
  });
}

// Start the server
app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
