const express = require("express");
const router = express.Router();
const pool = require("../database/db");
const bcrypt = require("bcrypt");
const {v4: uuidv4 } = require('uuid');
const { requireAuth } = require('../middleware/auth');

router.post("/register", async (req, res) => {
  const { email, password, nom, prenom } = req.body;
  // 1. Validation
  if (!email || !password) {
    return res.status(400).json({
      message: "Email or password missing !!!",
    });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // 2. Vérifier si email existe (requête paramétrée pour éviter injection SQL)
    const checkUser = await client.query(
      'SELECT id FROM utilisateurs WHERE email = $1',
      [email]
    );

    if (checkUser.rows.length > 0) {
      await client.query("ROLLBACK");
      return res.status(409).json({ message: "Email déjà existant" });
    }

    // 3. Hasher le mot de passe
    const passwordHash = await bcrypt.hash(password, 10);

    // 4. Insérer l'utilisateur (paramétré) et récupérer les champs demandés
    const result = await client.query(
      `INSERT INTO utilisateurs (email, password_hash, nom, prenom, actif)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, email, nom, prenom, date_creation`,
      [email, passwordHash, nom || null, prenom || null, true]
    );

    const newUser = result.rows[0];

    // 5. Assigner le rôle "user" via une sous-requête pour récupérer l'id du rôle
    await client.query(
      `INSERT INTO utilisateur_roles (utilisateur_id, role_id)
       VALUES ($1, (SELECT id FROM roles WHERE nom = $2))`,
      [newUser.id, 'user']
    );

    await client.query("COMMIT");

    res
      .status(201)
      .json({ message: "Utilisateur créé avec succès", user: newUser });
      
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Erreur création utilisateur:", error);
    res.status(500).json({ error: "Erreur serveur" });
  } finally {
    client.release();
  }
});


router.post('/login', async (req,res)=>{
    const {email, password} = req.body
    const client = await pool.connect()

    try{
        await client.query("BEGIN")

        // 1. Récupérer l'utilisateur
        const userResult = await client.query(
            'SELECT id, email, password_hash, nom, prenom, actif FROM utilisateurs WHERE email = $1',
            [email]
        )

        if(userResult.rows.length === 0){
            // Logger l'échec
            await client.query(
                `INSERT INTO logs_connexion (email_tentative, adresse_ip, user_agent, succes, message)
                 VALUES ($1, $2, $3, $4, $5)`,
                [email, req.ip, req.get('user-agent'), false, 'Email inconnu']
            )
            await client.query('COMMIT')
            return res.status(401).json({error: 'Email ou mot de passe incorrect'})
        }

        const user = userResult.rows[0]

        // 2. Vérifier si actif
        if(!user.actif){
            // Logger l'échec (compte inactif)
            await client.query(
                `INSERT INTO logs_connexion (utilisateur_id, email_tentative, adresse_ip, user_agent, succes, message)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [user.id, email, req.ip, req.get('user-agent'), false, 'Compte inactif']
            )
            await client.query('COMMIT')
            return res.status(403).json({error: 'Compte désactivé'})
        }

        // 3. Vérifier le mot de passe
        const passwordMatch = await bcrypt.compare(password, user.password_hash)

        if (!passwordMatch) {
            await client.query(
                `INSERT INTO logs_connexion (utilisateur_id, email_tentative, adresse_ip, user_agent, succes, message)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [user.id, email, req.ip, req.get('user-agent'), false, 'Mot de passe incorrect']
            )
            await client.query('COMMIT')
            return res.status(401).json({error: 'Email ou mot de passe incorrect'})
        }

        // 4. Générer token
        const token = uuidv4()
        const expiresAt = new Date()
        expiresAt.setHours(expiresAt.getHours() + 24)

        // 5. Créer session
        await client.query(
            `INSERT INTO sessions (utilisateur_id, token, date_expiration, actif)
             VALUES ($1, $2, $3, $4)`,
            [user.id, token, expiresAt, true]
        )

        // 6. Logger succès
        await client.query(
            `INSERT INTO logs_connexion (utilisateur_id, email_tentative, adresse_ip, user_agent, succes, message)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [user.id, email, req.ip, req.get('user-agent'), true, 'Connexion réussie']
        )

        await client.query('COMMIT')

        // 7. Retourner le token et les infos utilisateur
        res.json({
            message: 'Connexion réussie',
            token: token,
            user: {
                id: user.id,
                email: user.email,
                nom: user.nom,
                prenom: user.prenom
            },
            expiresAt: expiresAt
        })

    }catch(error){
        await client.query('ROLLBACK')
        console.error('Erreur login:', error)
        res.status(500).json({error:'Erreur serveur'})
        
    } finally{
      client.release()
    }
})

// GET /api/auth/profile 
router.get('/profile', requireAuth, async (req, res) => {
    try {
        // Récupérer l'utilisateur avec ses rôles 
        const result = await pool.query(
            `SELECT 
                u.id,
                u.email,
                u.nom,
                u.prenom,
                u.actif,
                u.date_creation,
                array_agg(r.nom) AS roles
             FROM utilisateurs u
             LEFT JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
             LEFT JOIN roles r ON ur.role_id = r.id
             WHERE u.id = $1
             GROUP BY u.id, u.email, u.nom, u.prenom, u.actif, u.date_creation`,
            [req.user.id]
        );

        res.json({ user: result.rows[0] });
    } catch (error) {
        console.error('Erreur profil:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// POST /api/auth/logout
router.post('/logout', requireAuth, async (req, res) => {
    const token = req.headers['authorization'];
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Désactiver la session
        const updateResult = await client.query(
            `UPDATE sessions 
             SET actif = false 
             WHERE token = $1 
             RETURNING utilisateur_id`,
            [token]
        );

        if (updateResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Session non trouvée' });
        }

        const userId = updateResult.rows[0].utilisateur_id;

        // 2. Logger la déconnexion dans logs_connexion
        await client.query(
            `INSERT INTO logs_connexion (utilisateur_id, email_tentative, adresse_ip, user_agent, succes, message)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [userId, req.user.email, req.ip, req.get('user-agent'), true, 'Déconnexion réussie']
        );

        await client.query('COMMIT');

        res.json({ message: 'Déconnexion réussie' });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Erreur logout:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    } finally {
        client.release();
    }
});

// GET /api/auth/logs 
router.get('/logs', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT 
                id,
                email_tentative,
                date_heure,
                adresse_ip,
                user_agent,
                succes,
                message
             FROM logs_connexion
             WHERE utilisateur_id = $1
             ORDER BY date_heure DESC
             LIMIT 50`,
            [req.user.id]
        );

        res.json({ logs: result.rows });
    } catch (error) {
        console.error('Erreur logs:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

module.exports = router

