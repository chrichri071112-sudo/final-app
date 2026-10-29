import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import dotenv from 'dotenv';
import { fileURLToPath } from 'node:url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const isProd = process.env.NODE_ENV === 'production';

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

app.use((_req, res, next) => {
  res.setHeader('Permissions-Policy', 'microphone=*');
  next();
});

// Cookie helper
function parseCookies(cookieHeader?: string): Record<string, string> {
  const list: Record<string, string> = {};
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach((cookie) => {
    let [name, ...rest] = cookie.split('=');
    name = name?.trim();
    if (!name) return;
    const value = rest.join('=').trim();
    list[name] = decodeURIComponent(value);
  });
  return list;
}

// User & Session types
interface JarvisUser {
  id: string;
  name: string;
  email: string;
  passwordHash?: string;
  provider: 'password' | 'google' | 'guest';
  authenticated: boolean;
  emailVerified: boolean;
  role: 'owner' | 'user';
  createdAt: string;
  plan: 'premium' | 'free';
  premiumSource: 'founder' | 'complimentary' | null;
  subscription: {
    status: 'active' | 'canceled' | 'none';
    provider?: string;
    currentPeriodEnd?: string | null;
  } | null;
}

interface StoredUser extends JarvisUser {
  passwordHash: string;
}

// Persistent user storage setup
const DATA_DIR = path.resolve(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const CREATOR_EMAIL = 'chrichri071112@gmail.com';
const CREATOR_PASSWORD = 'Christian2012';

function hashPassword(password: string): string {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function loadUsers(): Record<string, StoredUser> {
  let users: Record<string, StoredUser> = {};
  if (fs.existsSync(USERS_FILE)) {
    try {
      const data = fs.readFileSync(USERS_FILE, 'utf-8');
      users = JSON.parse(data);
    } catch {
      users = {};
    }
  }

  // Ensure creator account always exists with free lifetime premium (founder)
  users[CREATOR_EMAIL.toLowerCase()] = {
    id: 'creator-christian',
    name: 'Christian',
    email: CREATOR_EMAIL,
    passwordHash: hashPassword(CREATOR_PASSWORD),
    provider: 'password',
    authenticated: true,
    emailVerified: true,
    role: 'owner',
    createdAt: '2024-01-01T00:00:00.000Z',
    plan: 'premium',
    premiumSource: 'founder',
    subscription: {
      status: 'active',
      provider: 'founder',
      currentPeriodEnd: null,
    },
  };

  saveUsers(users);
  return users;
}

function saveUsers(users: Record<string, StoredUser>) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf-8');
  } catch (err) {
    console.error('Failed to save users:', err);
  }
}

let dbUsers = loadUsers();

// In-memory active sessions
const sessions = new Map<string, { user: JarvisUser; csrfToken: string; expiresAt: number }>();

function createSession(user: StoredUser): { sid: string; csrfToken: string; safeUser: JarvisUser } {
  const sid = crypto.randomBytes(32).toString('hex');
  const csrfToken = crypto.randomBytes(32).toString('hex');
  const { passwordHash, ...safeUser } = user;
  safeUser.authenticated = true;

  sessions.set(sid, {
    user: safeUser,
    csrfToken,
    expiresAt: Date.now() + 1000 * 60 * 60 * 24 * 30, // 30 days
  });

  return { sid, csrfToken, safeUser };
}

function sanitizeUser(user: StoredUser): JarvisUser {
  const { passwordHash, ...safe } = user;
  return safe;
}

// Global payout settings
let payoutSettings = {
  enabled: false,
  provider: 'stripe',
  businessName: 'JARVIS AURA',
  paymentLink: '',
  accountHolder: '',
  iban: '',
};

// -------------------------------------------------------------
// API Endpoints
// -------------------------------------------------------------

// 1. Session verification
app.get('/api/auth/session', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies.jarvis_sid;
  const session = sid ? sessions.get(sid) : undefined;

  if (session && session.expiresAt > Date.now()) {
    return res.json({
      csrfToken: session.csrfToken,
      googleClientId: '',
      googleNonce: crypto.randomBytes(16).toString('hex'),
      user: session.user,
    });
  }

  // Guest / visitor session
  const guestCsrf = crypto.randomBytes(32).toString('hex');
  return res.json({
    csrfToken: guestCsrf,
    googleClientId: '',
    googleNonce: crypto.randomBytes(16).toString('hex'),
    user: null,
  });
});

// 2. Login (Accedi)
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || typeof email !== 'string') {
    return res.status(400).json({ error: 'Inserisci un indirizzo email valido.' });
  }

  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Inserisci la password.' });
  }

  const cleanEmail = email.trim().toLowerCase();

  // Special check for Creator / Founder
  if (cleanEmail === CREATOR_EMAIL.toLowerCase()) {
    if (password !== CREATOR_PASSWORD) {
      return res.status(401).json({
        error: 'Password errata per l\'account del creatore. Accesso riservato protetto da password.',
      });
    }

    const creatorUser = dbUsers[cleanEmail];
    const { sid, csrfToken, safeUser } = createSession(creatorUser);

    res.setHeader(
      'Set-Cookie',
      `jarvis_sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 30}`
    );

    return res.json({
      csrfToken,
      user: safeUser,
    });
  }

  // Other users
  const existing = dbUsers[cleanEmail];
  if (!existing) {
    return res.status(404).json({
      error: 'Nessun account trovato per questa email. Seleziona "Crea account" per registrarti.',
    });
  }

  const inputHash = hashPassword(password);
  if (existing.passwordHash !== inputHash && existing.passwordHash !== password) {
    return res.status(401).json({
      error: 'Password non corretta. Verifica le credenziali e riprova.',
    });
  }

  const { sid, csrfToken, safeUser } = createSession(existing);

  res.setHeader(
    'Set-Cookie',
    `jarvis_sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 30}`
  );

  return res.json({
    csrfToken,
    user: safeUser,
  });
});

// 3. Register (Crea account)
app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body;

  if (!name || typeof name !== 'string' || name.trim().length < 2) {
    return res.status(400).json({ error: 'Inserisci un nome valido (almeno 2 caratteri).' });
  }

  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'Inserisci un indirizzo email valido.' });
  }

  if (!password || typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ error: 'La password deve contenere almeno 6 caratteri.' });
  }

  const cleanEmail = email.trim().toLowerCase();

  // If registering as creator's email:
  if (cleanEmail === CREATOR_EMAIL.toLowerCase()) {
    if (password === CREATOR_PASSWORD) {
      const creatorUser = dbUsers[cleanEmail];
      const { sid, csrfToken, safeUser } = createSession(creatorUser);
      res.setHeader(
        'Set-Cookie',
        `jarvis_sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 30}`
      );
      return res.json({ csrfToken, user: safeUser });
    }
    return res.status(400).json({
      error: 'Questo indirizzo email appartiene al creatore ed è protetto. Se sei il creatore, usa "Accedi" con la tua password riservata.',
    });
  }

  if (dbUsers[cleanEmail]) {
    return res.status(400).json({
      error: 'Esiste già un account registrato con questa email. Passa ad "Accedi" per entrare.',
    });
  }

  const newUser: StoredUser = {
    id: `user_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
    name: name.trim(),
    email: cleanEmail,
    passwordHash: hashPassword(password),
    provider: 'password',
    authenticated: true,
    emailVerified: true,
    role: 'user',
    createdAt: new Date().toISOString(),
    plan: 'free',
    premiumSource: null,
    subscription: null,
  };

  dbUsers[cleanEmail] = newUser;
  saveUsers(dbUsers);

  const { sid, csrfToken, safeUser } = createSession(newUser);

  res.setHeader(
    'Set-Cookie',
    `jarvis_sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 30}`
  );

  return res.json({
    csrfToken,
    user: safeUser,
  });
});

// 4. Google Auth Protection
app.post('/api/auth/google', (_req, res) => {
  return res.status(401).json({
    error: 'Accesso protetto da password: per garantire la sicurezza del tuo account personale, accedi inserendo email e password.',
  });
});

// 5. Logout
app.post('/api/auth/logout', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies.jarvis_sid;
  if (sid) {
    sessions.delete(sid);
  }
  res.setHeader('Set-Cookie', 'jarvis_sid=; Path=/; HttpOnly; Max-Age=0');
  const freshCsrf = crypto.randomBytes(32).toString('hex');
  return res.json({ ok: true, csrfToken: freshCsrf });
});

// 6. Verification stubs
app.post('/api/auth/verify-email', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies.jarvis_sid;
  const session = sid ? sessions.get(sid) : undefined;
  if (session) {
    session.user.emailVerified = true;
    return res.json({ csrfToken: session.csrfToken, user: session.user });
  }
  return res.status(401).json({ error: 'Nessuna sessione attiva.' });
});

app.post('/api/auth/resend-verification', (_req, res) => {
  return res.json({ ok: true });
});

// 7. Payout settings
app.get('/api/billing/method', (_req, res) => {
  return res.json({ payout: payoutSettings });
});

app.get('/api/admin/payout', (_req, res) => {
  return res.json({ payout: payoutSettings });
});

app.post('/api/admin/payout', (req, res) => {
  payoutSettings = { ...payoutSettings, ...req.body };
  return res.json({ payout: payoutSettings });
});

// 8. Server Config for JARVIS
app.get('/api/config', (_req, res) => {
  return res.json({
    configured: true,
    authorized: true,
    supportsWebSearch: true,
    model: 'gemini-2.5-flash',
    googleClientId: '',
  });
});

// 9. AI Chat endpoint
app.post('/api/chat', async (req, res) => {
  const { query, history } = req.body;

  if (!query || typeof query !== 'string') {
    return res.status(400).json({ error: 'Richiesta non valida.' });
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (apiKey) {
    try {
      const { GoogleGenAI } = await import('@google/genai');
      const ai = new GoogleGenAI({ apiKey });

      // Build conversation contents
      const contents: Array<{ role: 'user' | 'model'; parts: Array<{ text: string }> }> = [];

      if (Array.isArray(history)) {
        for (const item of history.slice(-8)) {
          if (item && item.text) {
            contents.push({
              role: item.role === 'assistant' ? 'model' : 'user',
              parts: [{ text: String(item.text) }],
            });
          }
        }
      }

      contents.push({
        role: 'user',
        parts: [{ text: query }],
      });

      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents,
        config: {
          systemInstruction:
            'Sei JARVIS AURA, l\'intelligenza artificiale avanzata e centro di comando personale. Rispondi sempre in italiano in modo chiaro, autorevole, brillante ed empatico, assistendo l\'utente con spiegazioni, pianificazioni, calcoli o analisi contestuali.',
          temperature: 0.7,
        },
      });

      const responseText = response.text || 'JARVIS AURA: ho elaborato la richiesta.';
      return res.json({
        text: responseText,
        model: 'gemini-2.5-flash',
        provider: 'server',
        webSearched: false,
        sources: [],
      });
    } catch (err: any) {
      console.error('Gemini API error:', err);
    }
  }

  // Fallback intelligent response
  return res.json({
    text: `JARVIS AURA ha ricevuto il messaggio: "${query}". Sistemi operativi e contesto sincronizzati.`,
    model: 'jarvis-core',
    provider: 'server',
    webSearched: false,
    sources: [],
  });
});

// 10. Voice processing endpoint (Gemini Multimodal Audio Transcription)
app.post('/api/voice', async (req, res) => {
  const { audio, mimeType = 'audio/webm' } = req.body;

  if (!audio || typeof audio !== 'string') {
    return res.status(400).json({ error: 'Nessun flusso audio valido ricevuto dal microfono.' });
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (apiKey) {
    try {
      const { GoogleGenAI } = await import('@google/genai');
      const ai = new GoogleGenAI({ apiKey });

      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: [
          {
            role: 'user',
            parts: [
              {
                inlineData: {
                  mimeType,
                  data: audio,
                },
              },
              {
                text: 'Trascrivi esattamente in italiano le parole dette dall\'utente in questo audio e rispondi come JARVIS AURA. Rispondi SEMPRE e SOLO in formato JSON: {"userText": "testo pronunciato dall\'utente", "replyText": "risposta intelligente di JARVIS in italiano"}',
              },
            ],
          },
        ],
        config: {
          responseMimeType: 'application/json',
          systemInstruction:
            'Sei JARVIS AURA. Ascolta con precisione l\'audio registrato dal microfono, estrai esattamente le parole dell\'utente nel campo userText e fornisci la tua risposta in replyText.',
        },
      });

      const parsed = JSON.parse(response.text || '{}');
      const userText = parsed.userText || 'Comando vocale';
      const replyText = parsed.replyText || 'Comando vocale elaborato con successo da JARVIS.';

      return res.json({
        userText,
        text: replyText,
        model: 'gemini-2.5-flash',
        provider: 'server',
      });
    } catch (err: any) {
      console.error('Gemini Voice processing error:', err);
    }
  }

  return res.json({
    userText: 'Comando vocale',
    text: 'JARVIS ha acquisito il tuo comando vocale dal microfono.',
    model: 'jarvis-core',
    provider: 'server',
  });
});

// -------------------------------------------------------------
// Vite middleware in dev or static files in prod
// -------------------------------------------------------------
async function startServer() {
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`JARVIS AURA server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
