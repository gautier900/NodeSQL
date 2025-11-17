const express = require('express');
const router = express.Router();
const pool = require('../database/db');
const { requireAuth, requirePermission } = require('../middleware/auth');

// GET /api/users?page=1&limit=10
router.get('/',
    requireAuth,
    requirePermission('users', 'read'),
    async (req, res) => {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const offset = (page - 1) * limit;

        try {
            const countResult = await pool.query(
                'SELECT COUNT(*) as total FROM utilisateurs'
            );
            const total = parseInt(countResult.rows[0].total);

            const usersResult = await pool.query(
                `SELECT u.id, u.email, u.nom, u.prenom, u.actif, u.date_creation, array_agg(r.nom) FILTER (WHERE r.nom IS NOT NULL) AS roles
                 FROM utilisateurs u
                 LEFT JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
                 LEFT JOIN roles r ON ur.role_id = r.id
                 GROUP BY u.id, u.email, u.nom, u.prenom, u.actif, u.date_creation
                 ORDER BY u.id
                 LIMIT $1 OFFSET $2`,
                [limit, offset]
            );

            res.json({
                users: usersResult.rows,
                pagination: {
                    page: page,
                    limit: limit,
                    total: total,
                    totalPages: Math.ceil(total / limit)
                }
            });

        } catch (error) {
            console.error('Erreur liste utilisateurs:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
);

// PUT /api/users/:id - Mettre à jour un utilisateur
router.put('/:id',
    requireAuth,
    requirePermission('users', 'write'),
    async (req, res) => {
        const { id } = req.params;
        const { nom, prenom, actif } = req.body;

        const userId = parseInt(id);

        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const checkUser = await client.query(
                'SELECT id FROM utilisateurs WHERE id = $1',
                [userId]
            );

            if (checkUser.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json({ error: 'Utilisateur non trouvé' });
            }

            const result = await pool.query(
                `UPDATE utilisateurs 
                 SET nom = $1, prenom = $2, actif = $3
                 WHERE id = $4
                 RETURNING id, email, nom, prenom, actif, date_creation`,
                [nom || null, prenom || null, actif !== undefined ? actif : true, userId]
            );

            await client.query('COMMIT');

            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'Utilisateur non trouvé' });
            }

            res.json({
                message: 'Utilisateur mis à jour',
                user: result.rows[0]
            });

        } catch (error) {
            await client.query('ROLLBACK');
            console.error('Erreur mise à jour utilisateur:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
);

// DELETE /api/users/:id - Supprimer un utilisateur
router.delete('/:id',
    requireAuth,
    requirePermission('users', 'delete'),
    async (req, res) => {
        const { id } = req.params;
 

        if (parseInt(id) === req.user.id) {
            return res.status(403).json({ 
                error: 'Vous ne pouvez pas vous supprimer vous-même' 
            });
        }

        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            // Vérifier que l'utilisateur existe
            const checkUser = await client.query(
                'SELECT id, email FROM utilisateurs WHERE id = $1',
                [parseInt(id)]
            );

            if (checkUser.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json({ error: 'Utilisateur non trouvé' });
            }

            // Supprimer l'utilisateur (CASCADE supprimera aussi les entrées dans utilisateur_roles, sessions, etc.)
            await client.query(
                'DELETE FROM utilisateurs WHERE id = $1',
                [parseInt(id)]
            );

            await client.query('COMMIT');

            res.json({ 
                message: 'Utilisateur supprimé',
                deletedUser: checkUser.rows[0]
            });

        } catch (error) {
            await client.query('ROLLBACK');
            console.error('Erreur suppression utilisateur:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        } finally {
            client.release();
        }
    }
);

// GET /api/users/:id/permissions - Récupérer toutes les permissions d'un utilisateur
router.get('/:id/permissions',
    requireAuth,
    async (req, res) => {
        const { id } = req.params;
        const userId = parseInt(id);

        try {
            // Récupérer toutes les permissions de l'utilisateur via ses rôles
            const result = await pool.query(
                `SELECT DISTINCT 
                    p.nom, 
                    p.ressource, 
                    p.action, 
                    p.description
                 FROM utilisateurs u
                 INNER JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
                 INNER JOIN role_permissions rp ON ur.role_id = rp.role_id
                 INNER JOIN permissions p ON rp.permission_id = p.id
                 WHERE u.id = $1
                 ORDER BY p.ressource, p.action`,
                [userId]
            );

            res.json({
                utilisateur_id: userId,
                permissions: result.rows
            });

        } catch (error) {
            console.error('Erreur récupération permissions:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
);

// GET /api/users/:id/permissions/:ressource/:action - Vérifier si un utilisateur a une permission spécifique
router.get('/:id/permissions/:ressource/:action',
    requireAuth,
    async (req, res) => {
        const { id, ressource, action } = req.params;
        const userId = parseInt(id);

        try {
            // Utiliser la fonction PostgreSQL utilisateur_a_permission
            const result = await pool.query(
                'SELECT utilisateur_a_permission($1, $2, $3) AS has_permission',
                [userId, ressource, action]
            );

            const hasPermission = result.rows[0].has_permission;

            res.json({
                utilisateur_id: userId,
                ressource: ressource,
                action: action,
                has_permission: hasPermission
            });

        } catch (error) {
            console.error('Erreur vérification permission:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
);

module.exports = router;
