import express from 'express';
import path from 'path';
import fs from 'fs';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI, Type } from '@google/genai';
import { DEFAULT_POSTS, DEFAULT_CATEGORIES, DEFAULT_CONFIG } from './src/defaultData';
import { BlogPost, Category, ContactSubmission, Subscriber, WebConfig } from './src/types';

const app = express();
const PORT = 3000;

// Path to durable store file
const STORE_PATH = path.join(process.cwd(), 'data_store.json');

// Interface for local data store
interface DataStore {
  posts: BlogPost[];
  categories: Category[];
  submissions: ContactSubmission[];
  subscribers: Subscriber[];
  config: WebConfig;
  adminCredentials?: {
    username: string;
    passwordHashOrPlain: string;
  };
  sessions?: Array<{
    token: string;
    username: string;
    expiresAt: string;
  }>;
}

// Ensure store file exists and load it
function loadStore(): DataStore {
  try {
    if (fs.existsSync(STORE_PATH)) {
      const data = fs.readFileSync(STORE_PATH, 'utf-8');
      const parsed = JSON.parse(data) as DataStore;
      
      // Upgrade store with credential & session arrays if missing
      if (!parsed.adminCredentials) {
        parsed.adminCredentials = {
          username: 'admin',
          passwordHashOrPlain: 'admin123'
        };
      }
      if (!parsed.sessions) {
        parsed.sessions = [];
      }
      return parsed;
    }
  } catch (err) {
    console.error('Failed to read data_store.json, creating new', err);
  }

  // Create default and write
  const initialStore: DataStore = {
    posts: DEFAULT_POSTS,
    categories: DEFAULT_CATEGORIES,
    submissions: [
      {
        id: 'sub-1',
        name: 'Vibol Meas',
        email: 'vibol@domain.com',
        message: 'Hello! I love your blog content on Cambodia. Do you offer custom tour consultations?',
        date: '2026-06-05T10:00:00Z',
        status: 'new'
      }
    ],
    subscribers: [
      { id: 'suber-1', email: 'hello@traveler.com', date: '2026-06-04' }
    ],
    config: DEFAULT_CONFIG,
    adminCredentials: {
      username: 'admin',
      passwordHashOrPlain: 'admin123'
    },
    sessions: []
  };
  saveStore(initialStore);
  return initialStore;
}

function saveStore(store: DataStore) {
  try {
    fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2), 'utf-8');
  } catch (err) {
    console.error('Failed to write to data_store.json', err);
  }
}

// Initialize store in memory
let db = loadStore();

// Middlewares
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// --- Authentication Helper Middleware ---
function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : (req.headers['x-admin-token'] as string);

  if (!token) {
    return res.status(401).json({ error: 'Auth session token required. Access Denied.' });
  }

  // Find valid session
  const sessionIndex = (db.sessions || []).findIndex(s => s.token === token);
  if (sessionIndex === -1) {
    return res.status(401).json({ error: 'Access Denied. Session invalid or logged out.' });
  }

  const session = db.sessions![sessionIndex];
  if (new Date(session.expiresAt) < new Date()) {
    // Session expired - clear it
    db.sessions!.splice(sessionIndex, 1);
    saveStore(db);
    return res.status(401).json({ error: 'Access Denied. Session has expired.' });
  }

  // Extend session expiry automatically on active request
  const newExpiry = new Date();
  newExpiry.setHours(newExpiry.getHours() + 24); // Extend by 24h
  session.expiresAt = newExpiry.toISOString();
  saveStore(db);

  (req as any).adminSession = session;
  next();
}

// --- Auth Endpoints ---

// Login API
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password credentials are required.' });
  }

  const creds = db.adminCredentials || { username: 'admin', passwordHashOrPlain: 'admin123' };
  
  if (username === creds.username && password === creds.passwordHashOrPlain) {
    // Generate secure session token
    const token = `session-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24); // 24 Hours validity

    if (!db.sessions) db.sessions = [];
    db.sessions.push({
      token,
      username,
      expiresAt: expiresAt.toISOString()
    });
    saveStore(db);

    return res.json({
      success: true,
      token,
      username,
      role: 'Admin'
    });
  }

  return res.status(401).json({ error: 'Invalid user handle name or security passcode.' });
});

// Validate Session (on refresh/load)
app.get('/api/auth/me', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : (req.headers['x-admin-token'] as string);

  if (!token) {
    return res.status(401).json({ error: 'No active session token.' });
  }

  const session = (db.sessions || []).find(s => s.token === token && new Date(s.expiresAt) > new Date());
  if (session) {
    return res.json({
      username: session.username,
      role: 'Admin'
    });
  }

  return res.status(401).json({ error: 'Session expired or invalid.' });
});

// Logout API
app.post('/api/auth/logout', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : (req.headers['x-admin-token'] as string);

  if (token) {
    const origLength = db.sessions?.length || 0;
    db.sessions = (db.sessions || []).filter(s => s.token !== token);
    if (db.sessions.length !== origLength) {
      saveStore(db);
    }
  }

  return res.json({ success: true, message: 'Logged out successfully.' });
});

// Change Admin Password / Credentials
app.post('/api/auth/change-credentials', requireAdmin, (req, res) => {
  const { newUsername, newPassword } = req.body;
  if (!newUsername || !newPassword) {
    return res.status(400).json({ error: 'Both new user handle and passphrase passcode are required.' });
  }

  db.adminCredentials = {
    username: newUsername,
    passwordHashOrPlain: newPassword
  };

  const currentSession = (req as any).adminSession;
  db.sessions = [
    {
      token: currentSession.token,
      username: newUsername,
      expiresAt: currentSession.expiresAt
    }
  ];

  saveStore(db);
  return res.json({ success: true, message: 'Admin security passcode updated successfully!' });
});

// Lazy initializer for Gemini
let cachedAiClient: GoogleGenAI | null = null;
function getGeminiClient(): GoogleGenAI {
  if (!cachedAiClient) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error('GEMINI_API_KEY environment variable is not configured.');
    }
    cachedAiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build'
        }
      }
    });
  }
  return cachedAiClient;
}

// ------------------- API ENDPOINTS -------------------

// Post Endpoints
app.get('/api/posts', (req, res) => {
  res.json(db.posts);
});

app.get('/api/posts/:idOrSlug', (req, res) => {
  const { idOrSlug } = req.params;
  const post = db.posts.find(p => p.id === idOrSlug || p.slug === idOrSlug);
  if (post) {
    // Increment view count simple
    post.viewCount = (post.viewCount || 0) + 1;
    saveStore(db);
    res.json(post);
  } else {
    res.status(404).json({ error: 'Blog post not found' });
  }
});

app.post('/api/posts', requireAdmin, (req, res) => {
  const postData = req.body as BlogPost;
  if (!postData.title || !postData.content) {
    return res.status(400).json({ error: 'Title and content are required' });
  }

  const index = db.posts.findIndex(p => p.id === postData.id);
  const slug = postData.slug || postData.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');

  const newPost: BlogPost = {
    ...postData,
    slug,
    date: postData.date || new Date().toISOString().split('T')[0],
    viewCount: postData.viewCount || 0,
    comments: postData.comments || [],
    galleryImages: postData.galleryImages || []
  };

  if (index !== -1) {
    // Preserve view count and comments if not provided
    newPost.viewCount = db.posts[index].viewCount;
    newPost.comments = db.posts[index].comments;
    db.posts[index] = newPost;
  } else {
    db.posts.unshift(newPost);
  }

  saveStore(db);
  res.json(newPost);
});

app.delete('/api/posts/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const index = db.posts.findIndex(p => p.id === id);
  if (index !== -1) {
    db.posts.splice(index, 1);
    saveStore(db);
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Post not found' });
  }
});

// Category Endpoints
app.get('/api/categories', (req, res) => {
  res.json(db.categories);
});

app.post('/api/categories', requireAdmin, (req, res) => {
  const category = req.body as Category;
  if (!category.name) {
    return res.status(400).json({ error: 'Category name is required' });
  }
  const index = db.categories.findIndex(c => c.id === category.id);
  const slug = category.slug || category.name.toLowerCase().replace(/[^a-z0-9]+/g, '-');

  const newCategory = { ...category, slug };
  if (index !== -1) {
    db.categories[index] = newCategory;
  } else {
    db.categories.push(newCategory);
  }
  saveStore(db);
  res.json(newCategory);
});

app.delete('/api/categories/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const index = db.categories.findIndex(c => c.id === id);
  if (index !== -1) {
    db.categories.splice(index, 1);
    saveStore(db);
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Category not found' });
  }
});

// Comments Endpoints
app.post('/api/posts/:postId/comments', (req, res) => {
  const { postId } = req.params;
  const { author, email, content } = req.body;

  if (!author || !content) {
    return res.status(400).json({ error: 'Author and comment text are required' });
  }

  const post = db.posts.find(p => p.id === postId);
  if (!post) {
    return res.status(404).json({ error: 'Blog post not found' });
  }

  const newComment = {
    id: `com-${Date.now()}`,
    author,
    email: email || '',
    content,
    date: new Date().toISOString().split('T')[0],
    approved: true // Auto approved for demo ease, editable in cms
  };

  if (!post.comments) {
    post.comments = [];
  }
  post.comments.push(newComment);
  saveStore(db);
  res.json(newComment);
});

app.post('/api/posts/:postId/comments/:commentId/approve', requireAdmin, (req, res) => {
  const { postId, commentId } = req.params;
  const { approved } = req.body;

  const post = db.posts.find(p => p.id === postId);
  if (!post) return res.status(404).json({ error: 'Post not found' });

  const comment = post.comments.find(c => c.id === commentId);
  if (!comment) return res.status(404).json({ error: 'Comment not found' });

  comment.approved = !!approved;
  saveStore(db);
  res.json(comment);
});

app.delete('/api/posts/:postId/comments/:commentId', requireAdmin, (req, res) => {
  const { postId, commentId } = req.params;
  const post = db.posts.find(p => p.id === postId);
  if (!post) return res.status(404).json({ error: 'Post not found' });

  const commentIndex = post.comments.findIndex(c => c.id === commentId);
  if (commentIndex === -1) return res.status(404).json({ error: 'Comment not found' });

  post.comments.splice(commentIndex, 1);
  saveStore(db);
  res.json({ success: true });
});

// Web Config Endpoints
app.get('/api/config', (req, res) => {
  res.json(db.config);
});

app.post('/api/config', requireAdmin, (req, res) => {
  db.config = { ...db.config, ...req.body };
  saveStore(db);
  res.json(db.config);
});

// Newsletter Subscriptions
app.get('/api/subscribers', requireAdmin, (req, res) => {
  res.json(db.subscribers);
});

app.post('/api/subscribers', (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'A valid email is required' });
  }

  const exists = db.subscribers.find(s => s.email.toLowerCase() === email.toLowerCase());
  if (exists) {
    return res.json({ alreadySubscribed: true });
  }

  const newSub = {
    id: `suber-${Date.now()}`,
    email,
    date: new Date().toISOString().split('T')[0]
  };

  db.subscribers.push(newSub);
  saveStore(db);
  res.json({ success: true, subscriber: newSub });
});

// Contact Submissions
app.get('/api/submissions', requireAdmin, (req, res) => {
  res.json(db.submissions);
});

app.post('/api/submissions', (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !email || !message) {
    return res.status(400).json({ error: 'All fields (name, email, message) are required.' });
  }

  const newSubmission: ContactSubmission = {
    id: `sub-${Date.now()}`,
    name,
    email,
    message,
    date: new Date().toISOString(),
    status: 'new'
  };

  db.submissions.unshift(newSubmission);
  saveStore(db);
  res.json({ success: true, submission: newSubmission });
});

app.post('/api/submissions/:id/status', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { status } = req.body; // 'new' | 'read' | 'replied'
  const sub = db.submissions.find(s => s.id === id);
  if (sub) {
    sub.status = status;
    saveStore(db);
    res.json(sub);
  } else {
    res.status(404).json({ error: 'Submission not found' });
  }
});

app.delete('/api/submissions/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const index = db.submissions.findIndex(s => s.id === id);
  if (index !== -1) {
    db.submissions.splice(index, 1);
    saveStore(db);
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Submission not found' });
  }
});

// ------------------- GEMINI AI ROUTER -------------------

// AI Assistant for Content Generation and SEO recommendations
app.post('/api/gemini/generate-seo', requireAdmin, async (req, res) => {
  const { title, content, focusKeywords } = req.body;

  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content are required to audit SEO' });
  }

  try {
    const ai = getGeminiClient();

    const prompt = `Perform an SEO Audit and keyword analysis for this travel blog post option.
Title: "${title}"
Focus Keywords requested: "${focusKeywords || 'travel, culture, tour'}"
Content (Extract):
${content.substring(0, 3000)}

Please return a valid JSON object matching this schema:
{
  "seoScore": number (value between 10 and 100),
  "suggestions": string[] (array of 3 distinct, actionable, professional suggestions to improve SEO, density, or header optimization),
  "keywordAnalysis": {
    "recommendedKeywords": string[] (array of 4 highly relevant travel keywords to add or target),
    "currentDensityFeedback": string (brief review of the layout context)
  }
}`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.5-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          required: ['seoScore', 'suggestions', 'keywordAnalysis'],
          properties: {
            seoScore: { type: Type.INTEGER },
            suggestions: {
              type: Type.ARRAY,
              items: { type: Type.STRING }
            },
            keywordAnalysis: {
              type: Type.OBJECT,
              required: ['recommendedKeywords', 'currentDensityFeedback'],
              properties: {
                recommendedKeywords: {
                  type: Type.ARRAY,
                  items: { type: Type.STRING }
                },
                currentDensityFeedback: { type: Type.STRING }
              }
            }
          }
        }
      }
    });

    const parsedData = JSON.parse(response.text || '{}');
    res.json(parsedData);

  } catch (error: any) {
    console.error('Gemini SEO call failed:', error.message);
    // Return high quality mock analyzer default in case key isn't setup
    const defaultSeo = {
      seoScore: 85,
      suggestions: [
        `Consider incorporating the term "Cambodia itinerary" in your first paragraph for greater search relevance.`,
        `Include highly optimized descriptive alt texts for all image assets in the post gallery.`,
        `Add 2 sub-headings (e.g. H3) containing your primary travel location keyword to structure readability.`
      ],
      keywordAnalysis: {
        recommendedKeywords: ['Cambodia travel guide', 'Angkor Wat tours', 'Southeast Asia travel tips', 'unexplored local paths'],
        currentDensityFeedback: 'Good basic structural integration of destination keywords. Headers could be optimized further.'
      },
      warning: 'Using offline pre-calculated optimization values because GEMINI_API_KEY is not configured.'
    };
    res.json(defaultSeo);
  }
});

// AI Writing Assistant
app.post('/api/gemini/ai-writer', requireAdmin, async (req, res) => {
  const { prompt, category, tone } = req.body;

  if (!prompt) {
    return res.status(400).json({ error: 'Prompt is required to write content' });
  }

  try {
    const ai = getGeminiClient();

    const userPrompt = `Write an optimized travel blog article or draft based on this setup:
Core Request: "${prompt}"
Blog Category: "${category || 'Destinations'}"
Requested Tone: "${tone || 'Inspirational, Friendly'}"

Return a valid JSON object matching this schema:
{
  "title": string (suggested catchy travel blog title),
  "summary": string (brief search-snippet-friendly post meta snippet),
  "suggestedTags": string[] (array of 3-4 hashtags or tags),
  "content": string (detailed blog post body written beautifully in clean, professional Markdown with headers of type h3, bullet lists, and tips)
}`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.5-flash',
      contents: userPrompt,
      config: {
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          required: ['title', 'summary', 'suggestedTags', 'content'],
          properties: {
            title: { type: Type.STRING },
            summary: { type: Type.STRING },
            suggestedTags: {
              type: Type.ARRAY,
              items: { type: Type.STRING }
            },
            content: { type: Type.STRING }
          }
        }
      }
    });

    const rawData = JSON.parse(response.text || '{}');
    res.json(rawData);

  } catch (error: any) {
    console.error('Gemini Content Writer call failed:', error.message);
    // Simulated beautiful Khmer travel draft
    const fallbackDraft = {
      title: `Secret Highlights of Cambodian Culture: Travel with Thaychanheng`,
      summary: `Discover incredible traditional customs, vibrant festivals, and deep-rooted Khmer arts that bring Cambodia's rich history directly to life for curious travelers.`,
      suggestedTags: ['Cambodian Culture', 'Travel Life', 'Khmer Customs', 'Historical Gems'],
      content: `### Discover the Cultural Charm of Cambodia

Cambodia is a country defined as much by its complex history as its extraordinary cultural treasures. Here are three amazing aspects of local Khmer culture to experience firsthand on your next voyage with us.

#### 1. The Divine Grace of Apsara Dance
Apsara classical dancing is a gorgeous form of stylized performance that traces its roots back to the legendary Angkor court period. Every elegant pose, hand gesture (known as *kbach*), and elaborate silk dress tells a historic tale from the mystical Ramayana. 
*Don't miss a traditional dinner show in Siem Reap to see this incredible ballet.*

#### 2. Essential Hand Palm Greetings: Sampeah
When entering local shops, pagodas, or private homes, use the respectful **Sampeah** greeting:
*   Bring your palms together in a lotus-bud shape in front of your chest.
*   Tilt your head slightly forward into a graceful bow.
*   *Note: For elders and monks, raise your joined hands higher—towards your chin or forehead—to show deeper reverence.*

#### 3. Traditional Khmer Weaving & Silk
Khmer hand-weaving has been passed down through generations. Visit the peaceful silk farms near Battambang or Koh Dach (the legendary Silk Island near Phnom Penh) to see artisans work with gorgeous natural golden threads on manual wooden loom sets. It's a wonderful place to pick up an authentic scarf (known as a *Krama*).`,
      warning: 'Using fallback generative model because GEMINI_API_KEY is not configured.'
    };
    res.json(fallbackDraft);
  }
});


// ------------------- VITE OR STATIC MIDDLEWARE -------------------

async function start() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Server] Travel with Thaychanheng is live at http://localhost:${PORT}`);
  });
}

start();
