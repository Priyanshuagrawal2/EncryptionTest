const express = require("express");
const crypto = require("crypto");
const bodyParser = require("body-parser");
const Memcached = require("memcached");

const app = express();
const port = 3001; // Make sure this doesn't conflict with your frontend port

// Initialize Memcached
const memcached = new Memcached("localhost:11211");

app.use(bodyParser.json());

// This would typically be stored securely, not in the code
const SERVER_SECRET = "your-server-secret-key";

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex")
    .slice(0, 16);
}

function encryptString(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(key), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
}

app.post("/api/verify-password", (req, res) => {
  const { password, uniqueString } = req.body;

  // In a real application, you would verify the password against a stored hash
  // For this example, we'll just check if the password is not empty
  if (!password) {
    return res.status(400).json({ error: "Invalid password" });
  }

  const hashedPassword = hashPassword(password);
  const encryptedString = encryptString(uniqueString, SERVER_SECRET);

  // Store the encrypted string in Memcached with a 1-hour expiration
  memcached.set(hashedPassword, encryptedString, 3600, (err) => {
    if (err) {
      console.error("Error storing in Memcached:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
    res.json({ success: true, hashedPassword });
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
