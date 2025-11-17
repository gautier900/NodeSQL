const { configDotenv } = require("dotenv");
const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
  user: process.env.DB_USER,
  // Utiliser socket Unix au lieu de TCP/IP pour éviter l'authentification par mot de passe
  host: process.env.DB_HOST === 'localhost' ? '/var/run/postgresql' : process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

pool.on("connect", () => {
  console.log("✅ Connecté à PostgreSQL");
});

pool.on("error", (err) => {
  console.error("❌ Erreur PostgreSQL:", err);
});

module.exports = pool;
