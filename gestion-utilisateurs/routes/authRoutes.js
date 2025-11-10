const express = require("express");
const router = express.Router();
const pool = require("../database/db");
const bcrypt = require("bcrypt");

router.post("/register", async (req, res) => {
  const { email, password, nom, prenom } = req.body;
  // 1.Validation
  if (!email || !password) {
    return res.status(400).json({
      message: "Email or password missing !!!",
    });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // 2. Vérifier si email existe
    const checkUser = await client.query(
      `SELECT id FROM utilisateurs WHERE email = ${email}`
    );

    if (checkUser.rows.length > 0) {
      return res.status(400).json({ message: "Email déjà existant" });
    }

    // 3. Hasher le mot de passe
    const passwordHash = await bcrypt.hash(password, 10);

    // 4. Insérer l'utilisateur (paramétré) et récupérer les champs demandés
    const result = await client.query(
      `INSERT INTO utilisateurs (email, password_hash, nom, prenom, actif)
             VALUES (${email}, ${passwordHash}, ${nom}, ${prenom}, ${actif})
             RETURNING id, email, nom, prenom, date_creation`
    );

    const newUser = result.rows[0];

    // 5. Assigner le rôle "user" via une sous-requête pour récupérer l'id du rôle
    await client.query(
      `INSERT INTO utilisateur_roles (utilisateur_id, role_id)
             VALUES (${newUser.id}, (SELECT id FROM roles WHERE nom = 'user'))`
    );

    await client.query("COMMIT");

    res
      .status(201)
      .json({ message: "Utilisateur créé avec succès", user: newUser });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Erruer création utilisateur:", error);
    res.status(500).json({ error: "Erruer serveur" });
  } finally {
    client.release();
  }
});

module.exports = router;
