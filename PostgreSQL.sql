CREATE TABLE utilisateurs (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    password_hash VARCHAR(255),
    nom VARCHAR(255),
    prenom VARCHAR(255),
    actif BOOLEAN,
    date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_utilisateurs_email ON utilisateurs(email);
CREATE INDEX idx_utilisateurs_actif ON utilisateurs(actif);

CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    nom VARCHAR(255) UNIQUE,
    description VARCHAR(255),
    date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    nom VARCHAR(255) UNIQUE,
    ressource VARCHAR(255),
    action VARCHAR(255),
    description VARCHAR(255),
    CONSTRAINT contrainte UNIQUE (ressource,action)
);

CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    nom VARCHAR(255) UNIQUE,
    ressource VARCHAR(255),
    action VARCHAR(255),
    description VARCHAR(255),
    CONSTRAINT contrainte UNIQUE (ressource,action)
);

CREATE TABLE utilisateur_roles (
    utilisateur_id INT REFERENCES utilisateurs(id) ON DELETE CASCADE,
    role_id INT REFERENCES roles(id) ON DELETE CASCADE,
    date_assignation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id,utilisateur_id)
);

CREATE TABLE role_permissions (
    role_id INT REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INT REFERENCES permissions(id) ON DELETE CASCADE,
    date_assignation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (permission_id, role_id)
);

CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    utilisateur_id INT REFERENCES utilisateurs(id),
    token VARCHAR(255) UNIQUE,
    date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    date_expiration TIMESTAMP,
    actif BOOLEAN
);

CREATE TABLE logs_connexion (
    id SERIAL PRIMARY KEY,
    utilisateur_id INT REFERENCES utilisateurs(id) ON DELETE SET NULL,
    email_tentative VARCHAR(255),
    date_heure TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    adresse_ip VARCHAR(255),
    user_agent VARCHAR(255),
    succes BOOLEAN,
    message VARCHAR(255)
);

INSERT INTO roles (nom, description) VALUES
 ('admin', 'Administrateur avec tous les droits'),
 ('moderator', 'Modérateur de contenu'),
 ('user', 'Utilisateur standard');

INSERT INTO permissions (nom, ressource, action, description) VALUES
 ('read_users', 'users', 'read', 'Lire les utilisateurs'),
 ('write_users', 'users', 'write', 'Créer/modifier des utilisateurs'),
 ('delete_users', 'users', 'delete', 'Supprimer des utilisateurs'),
 ('read_posts', 'posts', 'read', 'Lire les posts'),
 ('write_posts', 'posts', 'write', 'Créer/modifier des posts'),
 ('delete_posts', 'posts', 'delete', 'Supprimer des posts');

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.nom = 'admin';
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.id = p.id
WHERE r.nom = 'moderator'
AND p.nom IN ('read_users', 'read_posts', 'write_posts', 'delete_posts');


INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.id = p.id
WHERE r.nom = 'user'
AND p.nom IN ('read_users', 'read_posts', 'write_posts');

CREATE OR REPLACE FUNCTION utilisateur_a_permission(
    p_utilisateur_id INT,
    p_ressource VARCHAR,
    p_action VARCHAR
)
    RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT *
        FROM utilisateurs u
                 JOIN utilisateur_roles ur ON ur.utilisateur_id = u.id
                 JOIN role_permissions rp ON rp.role_id = ur.role_id
                 JOIN permissions p ON p.id = rp.permission_id
        WHERE u.id = p_utilisateur_id
          AND u.actif = true
          AND p.ressource = p_ressource
          AND p.action = p_action
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION est_token_valide(p_token VARCHAR)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM sessions s
        INNER JOIN utilisateurs u ON s.utilisateur_id = u.id
        WHERE s.token = p_token
          AND s.actif = true
          AND s.date_expiration > CURRENT_TIMESTAMP
          AND u.actif = true
    );
END;
$$ LANGUAGE plpgsql;

SELECT
    u.id,
    u.email,
    array_agg(r.nom) AS roles
FROM utilisateurs u
JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
JOIN roles r ON ur.role_id = r.id
WHERE u.id = 1
GROUP BY u.id, u.email;

SELECT DISTINCT
    u.id AS utilisateur_id,
    u.email,
    p.nom AS permission,
    p.ressource,
    p.action
FROM utilisateurs u
JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
JOIN role_permissions rp ON ur.role_id = rp.role_id
JOIN permissions p ON rp.permission_id = p.id
WHERE u.id = 1
ORDER BY p.ressource, p.action;

SELECT
    r.nom AS role,
    COUNT(ur.utilisateur_id) AS nombre_utilisateurs
FROM roles r
LEFT JOIN utilisateur_roles ur ON r.id = ur.role_id
GROUP BY r.nom
ORDER BY nombre_utilisateurs DESC;

SELECT
    u.id,
    u.email,
    array_agg(r.nom) AS roles
FROM utilisateurs u
JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
JOIN roles r ON ur.role_id = r.id
WHERE r.nom IN ('admin', 'moderator')
GROUP BY u.id, u.email
HAVING COUNT(DISTINCT r.nom) = 2;

SELECT
 DATE(date_heure) AS jour,
 COUNT(*) AS tentatives_echouees
FROM logs_connexion
WHERE succes = false
 AND date_heure >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY DATE(date_heure)
ORDER BY jour DESC;