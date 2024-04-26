import express from 'express';
import cors from 'cors';
import { prisma } from './lib/prisma';
import { JWTManager } from './lib/jwt';

const jwtManager = new JWTManager('UZJGEIUZHEUOZBuzeguzijgzhoezg23');

const app = express();
const PORT = 3400;

app.use(
  cors({
    origin: '*', // Autoriser toutes les origines
    methods: ['GET', 'POST', 'DELETE', 'UPDATE', 'PUT', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }),
);
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Bienvenue sur mon API shop online');
});

const isJwtValid = (req: express.Request) => {
  const jwt = req.headers.authorization;

  if (!jwt) {
    return false;
  }

  const isValid = jwtManager.verifyToken(jwt);

  if (!isValid.valid) {
    return false;
  }

  return true;
};

app.get('/users', async (req, res) => {
  try {
    const users = await prisma.users.findMany();

    if (isJwtValid(req)) {
      res.json(users);
    } else {
      res.status(401).json({ error: 'Token invalide' });
    }
  } catch (error) {
    if (error instanceof Error) {
      res.status(404).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
});

app.get('/user/:id', async (req, res) => {
  try {
    if (isJwtValid(req)) {
      const { id } = req.params;

      const user = await prisma.users.findUnique({
        where: {
          user_id: parseInt(id),
        },
      });

      res.json(user);
    } else {
      res.status(401).json({ error: 'Token invalide' });
    }
  } catch (error) {
    if (error instanceof Error) {
      res.status(404).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
});

app.post('/user/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await prisma.users.findFirst({
      where: {
        user_email: email,
      },
    });

    if (password !== user?.user_password) {
      res.status(401).json({ error: 'Mot de passe incorrect' });
      return;
    }

    // expire dans 10 minute
    const token = jwtManager.generateToken(
      {
        id: user?.user_id.toString()!,
        email: user?.user_email!,
        nom: user?.user_name!,
        prenom: user?.user_fname!,
      },
      '10m',
    );

    res.json({ token });
  } catch (error) {
    if (error instanceof Error) {
      res.status(404).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
});

app.post('/user', async (req, res) => {
  try {
    if (isJwtValid(req)) {
      const {
        user_name,
        user_email,
        user_phone,
        user_fname,
        user_lname,
        user_password,
        user_city,
        user_adress,
      } = req.body;

      if (
        !user_name ||
        !user_email ||
        !user_phone ||
        !user_fname ||
        !user_lname ||
        !user_password ||
        !user_city ||
        !user_adress
      ) {
        res.status(400).json({
          message: 'Veuillez fournir toutes les informations requises',
        });
        return;
      }

      // Simuler la création de l'utilisateur
      const newUser = {
        user_id: Math.floor(Math.random() * 10000), // Générer un ID fictif
        user_name,
        user_email,
        user_phone,
        user_fname,
        user_lname,
        user_password,
        user_city,
        user_adress,
      };

      const user = await prisma.users.create({
        data: newUser,
      });

      res.status(201).json(user);
    } else {
      res.status(401).json({ error: 'Token invalide' });
    }
  } catch (error) {
    if (error instanceof Error) {
      res.status(500).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
});

app.listen(PORT, () => {
  console.log(`Serveur en écoute sur http://localhost:${PORT}`);
});
