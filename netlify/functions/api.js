// netlify/functions/api.js
// Netlify Function (Node 18) qui expose une petite API REST-like
// vers une base MySQL hébergée sur InfinityFree, via mysql2/promise.
// Routes gérées via ?action=getUsers | register | login | deleteUser

const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// ---------------------------------------------------------------------------
// En-têtes CORS : autorise ton front (React ou HTML classique) à appeler
// cette function. Si tu veux restreindre, remplace '*' par ton domaine
// Netlify exact, ex: 'https://mon-site.netlify.app'
// ---------------------------------------------------------------------------
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
};

// Secret utilisé pour signer les tokens de connexion.
// A définir dans les variables d'environnement Netlify sous JWT_SECRET.
// Si absent, une valeur de secours est utilisée (à éviter en production).
const JWT_SECRET = process.env.JWT_SECRET || 'change-moi-en-production';

// Nombre de "rounds" pour le hachage bcrypt (10 est un bon compromis)
const SALT_ROUNDS = 10;

// Petit helper pour renvoyer une réponse JSON uniforme avec les headers CORS
function jsonResponse(statusCode, body) {
  return {
    statusCode,
    headers: {
      ...CORS_HEADERS,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  };
}

exports.handler = async function (event) {
  // Réponse aux requêtes preflight CORS (OPTIONS) envoyées par le navigateur
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: CORS_HEADERS, body: '' };
  }

  // Récupère l'action demandée depuis le query string (?action=...)
  const action = event.queryStringParameters && event.queryStringParameters.action;

  if (!action) {
    return jsonResponse(400, { error: 'Paramètre "action" manquant (?action=getUsers|register|login|deleteUser)' });
  }

  let connection;

  try {
    // ---------------------------------------------------------------------
    // Connexion à la base MySQL InfinityFree via les variables d'env
    // Configurées dans Netlify (Site settings > Environment variables)
    // et dans le fichier .env en local avec netlify-cli
    // ---------------------------------------------------------------------
    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
      // InfinityFree ferme parfois les connexions inactives : on met un
      // timeout de connexion raisonnable pour éviter de bloquer la function
      connectTimeout: 10000,
    });

    switch (action) {
      // -----------------------------------------------------------------
      // GET USERS : SELECT id, name, email, phone, created_at FROM users
      // (on ne renvoie jamais le mot de passe, même haché)
      // -----------------------------------------------------------------
      case 'getUsers': {
        const [rows] = await connection.execute(
          'SELECT id, name, email, phone, created_at FROM users'
        );
        return jsonResponse(200, { success: true, data: rows });
      }

      // -----------------------------------------------------------------
      // REGISTER : inscription — hache le mot de passe avant insertion
      // Body attendu : { name, email, password, phone? }
      // -----------------------------------------------------------------
      case 'register': {
        if (event.httpMethod !== 'POST') {
          return jsonResponse(405, { error: 'register nécessite une requête POST' });
        }

        const body = JSON.parse(event.body || '{}');
        const { name, email, password, phone } = body;

        if (!name || !email || !password) {
          return jsonResponse(400, { error: 'Champs "name", "email" et "password" requis' });
        }

        // Vérifie que l'email n'est pas déjà utilisé
        const [existing] = await connection.execute(
          'SELECT id FROM users WHERE email = ?',
          [email]
        );
        if (existing.length > 0) {
          return jsonResponse(409, { error: 'Cet email est déjà utilisé' });
        }

        // Hachage du mot de passe — jamais stocké en clair
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        // Requête préparée : évite toute injection SQL
        const [result] = await connection.execute(
          'INSERT INTO users (name, email, password, phone) VALUES (?, ?, ?, ?)',
          [name, email, passwordHash, phone || null]
        );

        // On génère directement un token pour connecter l'utilisateur
        // juste après son inscription
        const token = jwt.sign({ id: result.insertId, email }, JWT_SECRET, {
          expiresIn: '7d',
        });

        return jsonResponse(201, {
          success: true,
          message: 'Compte créé avec succès',
          token,
          user: { id: result.insertId, name, email, phone: phone || null },
        });
      }

      // -----------------------------------------------------------------
      // LOGIN : connexion — vérifie l'email + mot de passe haché
      // Body attendu : { email, password }
      // -----------------------------------------------------------------
      case 'login': {
        if (event.httpMethod !== 'POST') {
          return jsonResponse(405, { error: 'login nécessite une requête POST' });
        }

        const body = JSON.parse(event.body || '{}');
        const { email, password } = body;

        if (!email || !password) {
          return jsonResponse(400, { error: 'Champs "email" et "password" requis' });
        }

        const [rows] = await connection.execute(
          'SELECT id, name, email, password, phone FROM users WHERE email = ?',
          [email]
        );

        // Message volontairement générique (on ne dit pas si c'est
        // l'email ou le mot de passe qui est faux, pour la sécurité)
        if (rows.length === 0) {
          return jsonResponse(401, { error: 'Email ou mot de passe incorrect' });
        }

        const user = rows[0];
        const passwordMatches = await bcrypt.compare(password, user.password);

        if (!passwordMatches) {
          return jsonResponse(401, { error: 'Email ou mot de passe incorrect' });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
          expiresIn: '7d',
        });

        return jsonResponse(200, {
          success: true,
          message: 'Connexion réussie',
          token,
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
            phone: user.phone,
          },
        });
      }

      // -----------------------------------------------------------------
      // DELETE USER : DELETE FROM users WHERE id = ? — body JSON en POST
      // -----------------------------------------------------------------
      case 'deleteUser': {
        if (event.httpMethod !== 'POST') {
          return jsonResponse(405, { error: 'deleteUser nécessite une requête POST' });
        }

        const body = JSON.parse(event.body || '{}');
        const { id } = body;

        if (!id) {
          return jsonResponse(400, { error: 'Champ "id" requis' });
        }

        const [result] = await connection.execute(
          'DELETE FROM users WHERE id = ?',
          [id]
        );

        if (result.affectedRows === 0) {
          return jsonResponse(404, { error: `Aucun utilisateur trouvé avec l'id ${id}` });
        }

        return jsonResponse(200, { success: true, message: 'Utilisateur supprimé' });
      }

      default:
        return jsonResponse(400, { error: `Action inconnue: "${action}"` });
    }
  } catch (error) {
    // On log côté serveur (visible dans les logs Netlify Functions)
    console.error('Erreur API:', error);
    return jsonResponse(500, {
      error: 'Erreur serveur',
      details: error.message,
    });
  } finally {
    // Très important : on ferme toujours la connexion, même en cas d'erreur,
    // pour ne pas épuiser le quota de connexions simultanées d'InfinityFree
    if (connection) {
      await connection.end();
    }
  }
};
