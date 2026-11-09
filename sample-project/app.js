// CloudGuard Demonstration Fixture - Express Application Sample
const express = require('express');
const app = express();

// Dummy JWT Signing Key & Token for demonstration
const JWT_SECRET = "super_secret_jwt_signing_key_sample_789";
const DUMMY_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRlbW8gVXNlciJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// Benign parameters
const PORT = process.env.PORT || 3000;
const HEALTH_STATUS = "UP";

app.get('/health', (req, res) => {
  res.json({ status: HEALTH_STATUS, timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});

