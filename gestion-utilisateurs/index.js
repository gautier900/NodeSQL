const express = require("express");
const pool = require("./database/db");
const authRoutes = require("./routes/authRoutes");
const userRoutes = require("./routes/userRoutes");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);

// Health check
app.get("/api/health", async (req, res) => {
  try {
    const resultat = await pool.query("SELECT NOW()");
    const now = resultat.rows[0].now;
    return res.json({ status: "ok", now });
  } catch (error) {
    console.error("Health check error", error);
    return res
      .status(500)
      .json({ status: "error", message: "Connection failed" });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
});
