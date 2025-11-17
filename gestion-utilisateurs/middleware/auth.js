const pool = require('../database/db');

async function requireAuth(req, res, next) {
    const token = req.headers['authorization'];
    
    if (!token) {
        return res.status(401).json({ error: 'Token manquant' });
    }

    try {
        // Vérifier que le token est valide
        // JOIN avec utilisateurs pour récupérer les infos user
        // Vérifier: session active, date_expiration, utilisateur actif
        const result = await pool.query(
            `SELECT 
                u.id, 
                u.email, 
                u.nom, 
                u.prenom, 
                u.actif,
                s.token,
                s.date_expiration,
                s.actif AS session_active
             FROM sessions s
             JOIN utilisateurs u ON s.utilisateur_id = u.id
             WHERE s.token = $1 
               AND s.actif = true 
               AND s.date_expiration > NOW() 
               AND u.actif = true`,
            [token]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Token invalide ou expiré' });
        }

        
        req.user = result.rows[0];
        next();

    } catch (error) {
        console.error('Erreur middleware auth:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
}

function requirePermission(ressource, action) {
    return async (req, res, next) => {
    
        try {
            const result = await pool.query(
                'SELECT utilisateur_a_permission($1, $2, $3) AS has_permission',
                [req.user.id, ressource, action]
            );

            if (!result.rows[0].has_permission) {
                return res.status(403).json({ 
                    error: 'Permission refusée',
                    required: `${ressource}:${action}`
                });
            }

            next();

        } catch (error) {
            console.error('Erreur vérification permission:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    };
}

module.exports = { requireAuth, requirePermission };
