// netlify/functions/api.js
// Netlify Function (Node 18) qui expose une petite API REST-like
// vers une base MySQL hébergée sur InfinityFree, via mysql2/promise.
// Routes gérées via ?action=getUsers | addUser | deleteUser

const mysql = require('mysql2/promise');

// ---------------------------------------------------------------------------
// En-têtes CORS : autorise ton front React (ou toute origine) à appeler
// cette function. Si tu veux restreindre, remplace '*' par ton domaine
// Netlify exact, ex: 'https://mon-site.netlify.app'
// ---------------------------------------------------------------------------
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
};

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
    return jsonResponse(400, { error: 'Paramètre "action" manquant (?action=getUsers|addUser|deleteUser)' });
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
      // GET USERS : SELECT * FROM users
      // -----------------------------------------------------------------
      case 'getUsers': {
        const [rows] = await connection.execute('SELECT * FROM users');
        return jsonResponse(200, { success: true, data: rows });
      }

      // -----------------------------------------------------------------
      // ADD USER : INSERT INTO users (name, email) — body JSON en POST
      // -----------------------------------------------------------------
      case 'addUser': {
        if (event.httpMethod !== 'POST') {
          return jsonResponse(405, { error: 'addUser nécessite une requête POST' });
        }

        const body = JSON.parse(event.body || '{}');
        const { name, email } = body;

        if (!name || !email) {
          return jsonResponse(400, { error: 'Champs "name" et "email" requis' });
        }

        // Requête préparée : évite toute injection SQL
        const [result] = await connection.execute(
          'INSERT INTO users (name, email) VALUES (?, ?)',
          [name, email]
        );

        return jsonResponse(201, {
          success: true,
          message: 'Utilisateur ajouté',
          insertId: result.insertId,
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
