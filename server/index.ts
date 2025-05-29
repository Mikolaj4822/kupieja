import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import session from 'express-session';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { scrypt, randomBytes, timingSafeEqual } from 'crypto';
import { promisify } from 'util';
import { users, ads, responses, categories, type User, type InsertUser, type Ad, type InsertAd } from '../shared/schema.js';
import { eq, desc, like, and, or } from 'drizzle-orm';
import createMemoryStore from 'memorystore';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;
const scryptAsync = promisify(scrypt);

// Memory store for sessions and data
const MemoryStore = createMemoryStore(session);

// In-memory storage
const storage = {
  users: [] as User[],
  ads: [] as Ad[],
  responses: [] as any[],
  nextUserId: 1,
  nextAdId: 1,
  nextResponseId: 1,
};

// Initialize categories
const defaultCategories = [
  { id: 1, name: "Elektronika", icon: "cpu" },
  { id: 2, name: "Moda", icon: "shirt" },
  { id: 3, name: "Dom i Ogród", icon: "home" },
  { id: 4, name: "Motoryzacja", icon: "car" },
  { id: 5, name: "Usługi", icon: "briefcase" },
  { id: 6, name: "Zwierzęta", icon: "heart" },
  { id: 7, name: "Dla Dzieci", icon: "baby" },
  { id: 8, name: "Rozrywka", icon: "gamepad2" },
  { id: 9, name: "Muzyka i Edukacja", icon: "music" },
  { id: 10, name: "Sport i Hobby", icon: "dumbbell" },
  { id: 11, name: "Firma i Przemysł", icon: "building" },
  { id: 12, name: "Antyki i Kolekcje", icon: "crown" },
  { id: 13, name: "Zdrowie i Uroda", icon: "sparkles" },
  { id: 14, name: "Wypożyczalnia", icon: "clock" },
  { id: 15, name: "Noclegi", icon: "bed" },
  { id: 16, name: "Praca", icon: "briefcase" }
];

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'development-secret-key',
  resave: false,
  saveUninitialized: false,
  store: new MemoryStore({
    checkPeriod: 86400000
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// Passport configuration
async function hashPassword(password: string) {
  const salt = randomBytes(16).toString('hex');
  const buf = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${buf.toString('hex')}.${salt}`;
}

async function comparePasswords(supplied: string, stored: string) {
  const [hashed, salt] = stored.split('.');
  const hashedBuf = Buffer.from(hashed, 'hex');
  const suppliedBuf = (await scryptAsync(supplied, salt, 64)) as Buffer;
  return timingSafeEqual(hashedBuf, suppliedBuf);
}

passport.use(new LocalStrategy(async (username, password, done) => {
  const user = storage.users.find(u => u.username === username);
  if (!user || !(await comparePasswords(password, user.password))) {
    return done(null, false);
  }
  return done(null, user);
}));

passport.serializeUser((user: any, done) => done(null, user.id));
passport.deserializeUser((id: number, done) => {
  const user = storage.users.find(u => u.id === id);
  done(null, user || null);
});

// Auth routes
app.post('/api/register', async (req, res) => {
  const { username, email, password, fullName } = req.body;
  
  const existingUser = storage.users.find(u => u.username === username || u.email === email);
  if (existingUser) {
    return res.status(400).json({ error: 'Użytkownik już istnieje' });
  }

  const hashedPassword = await hashPassword(password);
  const newUser: User = {
    id: storage.nextUserId++,
    username,
    email,
    password: hashedPassword,
    fullName,
    createdAt: new Date()
  };

  storage.users.push(newUser);
  
  req.login(newUser, (err) => {
    if (err) return res.status(500).json({ error: 'Błąd logowania' });
    const { password: _, ...userWithoutPassword } = newUser;
    res.status(201).json(userWithoutPassword);
  });
});

app.post('/api/login', passport.authenticate('local'), (req, res) => {
  const { password: _, ...userWithoutPassword } = req.user as User;
  res.json(userWithoutPassword);
});

app.post('/api/logout', (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).json({ error: 'Błąd wylogowania' });
    res.json({ message: 'Wylogowano pomyślnie' });
  });
});

app.get('/api/user', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Nieautoryzowany' });
  }
  const { password: _, ...userWithoutPassword } = req.user as User;
  res.json(userWithoutPassword);
});

// Categories route
app.get('/api/categories', (req, res) => {
  res.json(defaultCategories);
});

// Ads routes
app.get('/api/ads', (req, res) => {
  let filteredAds = [...storage.ads];
  
  const { category, search, location } = req.query;
  
  if (category) {
    filteredAds = filteredAds.filter(ad => ad.categoryId === Number(category));
  }
  
  if (search) {
    const searchTerm = (search as string).toLowerCase();
    filteredAds = filteredAds.filter(ad => 
      ad.title.toLowerCase().includes(searchTerm) ||
      ad.description.toLowerCase().includes(searchTerm)
    );
  }
  
  if (location) {
    filteredAds = filteredAds.filter(ad => 
      ad.location.toLowerCase().includes((location as string).toLowerCase())
    );
  }
  
  // Sort by newest first
  filteredAds.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  
  res.json(filteredAds);
});

app.post('/api/ads', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Nieautoryzowany' });
  }

  const { title, description, categoryId, budgetRange, location, categoryFilters } = req.body;
  
  const newAd: Ad = {
    id: storage.nextAdId++,
    title,
    description,
    categoryId: Number(categoryId),
    budgetRange,
    location,
    categoryFilters: categoryFilters || {},
    userId: (req.user as User).id,
    createdAt: new Date(),
    updatedAt: new Date()
  };

  storage.ads.push(newAd);
  res.status(201).json(newAd);
});

app.get('/api/ads/:id', (req, res) => {
  const ad = storage.ads.find(a => a.id === Number(req.params.id));
  if (!ad) {
    return res.status(404).json({ error: 'Ogłoszenie nie znalezione' });
  }
  res.json(ad);
});

// Responses routes
app.get('/api/ads/:id/responses', (req, res) => {
  const adId = Number(req.params.id);
  const adResponses = storage.responses.filter(r => r.adId === adId);
  res.json(adResponses);
});

app.post('/api/ads/:id/responses', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Nieautoryzowany' });
  }

  const adId = Number(req.params.id);
  const { message, price } = req.body;
  
  const newResponse = {
    id: storage.nextResponseId++,
    adId,
    userId: (req.user as User).id,
    message,
    price: price ? Number(price) : null,
    createdAt: new Date()
  };

  storage.responses.push(newResponse);
  res.status(201).json(newResponse);
});

// Admin routes
app.delete('/api/admin/ads/:id', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Nieautoryzowany' });
  }

  const user = req.user as User;
  const isAdmin = user.email === 'admin@jakupie.pl';
  
  if (!isAdmin) {
    return res.status(403).json({ error: 'Brak uprawnień' });
  }

  const adId = Number(req.params.id);
  const adIndex = storage.ads.findIndex(a => a.id === adId);
  
  if (adIndex === -1) {
    return res.status(404).json({ error: 'Ogłoszenie nie znalezione' });
  }

  storage.ads.splice(adIndex, 1);
  res.json({ message: 'Ogłoszenie usunięte' });
});

// Serve static files in production
// Serve static files
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../dist')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../dist/index.html'));
  });
} else {
  // In development, serve client files
  app.use(express.static(path.join(__dirname, '../client')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/index.html'));
  });
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

export default app;