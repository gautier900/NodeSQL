const { configDotenv } = require("dotenv");
const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
  user: DB_USER,
  host: DB_HOST,
  database: DB_NAME,
  password: DB_PASSWORD,
  port: DB_PORT,
});

pool.on("connect", () => {
  console.log("✅ Connecté à PostgreSQL");
});

pool.on("error", (err) => {
  console.error("❌ Erreur PostgreSQL:", err);
});

module.exports = pool;
