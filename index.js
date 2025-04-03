const express = require('express');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;
const session = require('express-session');
const fs = require('fs');
const saml = require('saml2-js');
const bodyParser = require('body-parser');
const SQLiteStore = require('connect-sqlite3')(session); // ✅ Session persistence

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ Configure Express Session
//app.use(session({ secret: "supersecret", resave: false, saveUninitialized: true }));
// ✅ Configure Express Session with Persistent Store
app.use(session({
  secret: "supersecret",
  resave: false,
  saveUninitialized: false, // ✅ Prevents empty sessions
  store: new SQLiteStore(), // ✅ Stores sessions persistently
  cookie: {
    secure: false,  // Set to `true` if using HTTPS
    httpOnly: true,
    sameSite: "lax"
  }
}));
// Middleware to parse SAML responses
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// ✅ Generate SAML Metadata for the Service Provider (SP)
const spOptions = {
  entity_id: "https://35ea-93-174-85-223.ngrok-free.app", // Entity ID (Audience URI) - Use ngrok URL
  assert_endpoint: "https://35ea-93-174-85-223.ngrok-free.app/saml/acs", // ACS URL - Use ngrok URL
  certificate: fs.readFileSync('./certs/ngrok.crt', 'utf8'), // SP public certificate
  private_key: fs.readFileSync('./certs/ngrok.key', 'utf8'), // SP private key
};

const sp = new saml.ServiceProvider(spOptions);

// Generate and save SAML metadata
const metadata = sp.create_metadata();
fs.writeFileSync('saml_metadata.xml', metadata);
console.log('SAML metadata generated and saved to saml_metadata.xml');

// ✅ Configure Passport for SAML Authentication
passport.use(new SamlStrategy(
  {
    path: '/saml/acs', // ACS URL path
    entryPoint: 'https://portal.sso.ap-south-1.amazonaws.com/saml/assertion/NjM3NDIzMzU3Nzg0X2lucy1jMjA0ZTk4YjFkZjZiZWI2', // AWS IAM Identity Center SSO URL
    issuer: 'https://35ea-93-174-85-223.ngrok-free.app', // Entity ID (Audience URI) - Use ngrok URL
    cert: fs.readFileSync('aws_sso_cert.pem', 'utf8'), // AWS IAM Identity Center public certificate
    callbackUrl: 'https://35ea-93-174-85-223.ngrok-free.app/saml/acs', // ngrok URL
    // NEW ADDITIONS:
    identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    signatureAlgorithm: 'sha256',
    acceptedClockSkewMs: 10000,
    authnContext: ['urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'],
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
    additionalParams: {},
    attributeNames: {
      email: 'email',
      groups: 'Groups'  // Must match exactly what you defined in AWS SSO
    }
  },
  (profile, done) => {
    return done(null, profile);
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ✅ Initialize Passport
app.use(passport.initialize());
app.use(passport.session());
app.use((req, res, next) => {
    console.log(`🔍 Incoming Request: ${req.method} ${req.url}`);
    console.log("Headers:", req.headers);
    console.log("Body:", req.body);
    next();
});

// ✅ Middleware to Check if User is Authenticated
const isAuthenticated = (req, res, next) => {
  console.log("🔍 Checking authentication:", req.isAuthenticated());
  console.log("🔍 Session Data:", req.session);

  if (req.isAuthenticated()) {
    return next();
  }

  console.log("❌ User is not authenticated. Redirecting to login.");
  res.redirect('/login');
};

// ✅ Protected Route: Requires Authentication
app.get('/', isAuthenticated, (req, res) => {
  res.json({ message: "Hello, Yonder!" });
});

// ✅ Login Route (Redirects to AWS IAM Identity Center for SAML Authentication)
app.get('/login', passport.authenticate('saml'));

// ✅ Callback Route (Handles SAML Response from AWS IAM Identity Center)
// ✅ Callback Route (Handles SAML Response from Okta)
app.post('/saml/acs', 
  (req, res, next) => {
    console.log("📩 SAML Response Received:", req.body);
    next();
  },
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  (req, res) => {
    console.log("✅ User Authenticated:", req.user);
    
    // 🔹 Store User in Session Manually (FIX)
    req.session.user = req.user;
    req.session.save(err => {
      if (err) {
        console.error("⚠️ Session Save Error:", err);
      }
      res.redirect('/'); // 🔹 Redirect user to home page after login
    });
  }
);

// ✅ Logout Route (Clears Session & Redirects)
app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});