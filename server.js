const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const multer = require('multer');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const { sendClaimNotification } = require('./utils/mailer');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// --- DATABASE SETUP ---
const pool = new Pool({
    connectionString: `postgresql://${process.env.DB_USER}:${process.env.DB_PASS}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`
});

// --- MIDDLEWARE SETUP ---
app.set('view engine', 'ejs');
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "img-src": ["'self'", "data:", "https://placehold.co"], // Allow images from self and placehold.co
        },
    },
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // Middleware to parse JSON bodies
app.use(express.static(path.join(__dirname, 'public')));

// Session Middleware
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 // 1 day
    }
}));

// Multer setup
const storage = multer.diskStorage({
    destination: './public/uploads/',
    filename: function(req, file, cb) {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 2000000 },
    fileFilter: function(req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb('Error: Images Only!');
        }
    }
}).single('itemImage');

// Custom middleware to pass user info to all templates
app.use(async (req, res, next) => {
    res.locals.user = null;
    if (req.session.userId) {
        try {
            const result = await pool.query('SELECT id, name, email, role FROM users WHERE id = $1', [req.session.userId]);
            if (result.rows.length > 0) {
                res.locals.user = result.rows[0];
            }
        } catch (err) {
            console.error("Error fetching user for locals:", err);
        }
    }
    next();
});

// --- AUTH MIDDLEWARE ---
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
}

function requireGuest(req, res, next) {
    if (req.session.userId) {
        return res.redirect('/home');
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!res.locals.user || res.locals.user.role !== 'admin') {
        return res.status(403).send('Forbidden: Access is restricted to administrators.');
    }
    next();
}


// --- ROUTES ---

// Root redirects
app.get('/', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/home');
    }
    res.redirect('/login');
});

// New Homepage
app.get('/home', requireAuth, (req, res) => {
    res.render('home', { title: 'Home' });
});

// --- AUTHENTICATION ROUTES ---
app.get('/register', requireGuest, (req, res) => res.render('register', { title: 'Register', errors: [] }));

app.post('/register', requireGuest, [
    body('name', 'Name is required').notEmpty().trim().escape(),
    body('email', 'Please enter a valid email').isEmail().normalizeEmail(),
    body('password', 'Password must be at least 8 characters').isLength({ min: 8 }),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.render('register', { title: 'Register', errors: errors.array() });
    }
    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (name, email, password) VALUES ($1, $2, $3)',
            [name, email, hashedPassword]
        );
        res.redirect('/login');
    } catch (err) {
        console.error(err);
        res.render('register', { title: 'Register', errors: [{msg: 'Email already in use.'}] });
    }
});

app.get('/login', requireGuest, (req, res) => res.render('login', { title: 'Login', errors: [] }));

app.post('/login', requireGuest, [
    body('email', 'Please enter a valid email').isEmail().normalizeEmail(),
    body('password', 'Password is required').notEmpty()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.render('login', { title: 'Login', errors: errors.array() });
    }
    try {
        const { email, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.render('login', { title: 'Login', errors: [{ msg: 'Invalid credentials' }] });
        }
        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.render('login', { title: 'Login', errors: [{ msg: 'Invalid credentials' }] });
        }
        req.session.userId = user.id;
        res.redirect('/home');
    } catch (err) {
        console.error(err);
        res.render('login', { title: 'Login', errors: [{ msg: 'An error occurred during login.' }] });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/home');
        }
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});


// --- ITEM ROUTES ---

// List Items Page
app.get('/items', requireAuth, async (req, res) => {
    try {
        const { search = '', category = '', page = 1 } = req.query;
        const limit = 12;
        const offset = (page - 1) * limit;

        let baseQuery = `
            SELECT i.id, i.name, i.description, i.category, i.location, i.image_url, i.date_posted, u.name as poster_name 
            FROM items i
            JOIN users u ON i.user_id = u.id
            WHERE i.is_claimed = FALSE
        `;
        const queryParams = [];
        let paramIndex = 1;

        if (search) {
            baseQuery += ` AND (i.name ILIKE $${paramIndex} OR i.description ILIKE $${paramIndex})`;
            queryParams.push(`%${search}%`);
            paramIndex++;
        }
        if (category) {
            baseQuery += ` AND i.category = $${paramIndex}`;
            queryParams.push(category);
            paramIndex++;
        }

        const countQuery = `SELECT COUNT(*) FROM (${baseQuery.replace(/i\..*?,/g, 'i.id,').replace(/u\..*?,/g, '')}) AS filtered_items`;
        const countResult = await pool.query(countQuery, queryParams);
        const totalItems = parseInt(countResult.rows[0].count);
        const totalPages = Math.ceil(totalItems / limit);

        baseQuery += ` ORDER BY i.created_at DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
        queryParams.push(limit, offset);

        const result = await pool.query(baseQuery, queryParams);

        res.render('items', {
            title: 'Browse Items',
            items: result.rows,
            totalPages,
            currentPage: parseInt(page),
            search,
            category
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error fetching items');
    }
});

// ** ROUTE ORDER FIX **
// The '/items/new' route must be defined BEFORE the '/items/:id' route.
// Otherwise, Express will think "new" is an item ID.

// New Item Form
app.get('/items/new', requireAuth, (req, res) => {
    const { category } = req.query;
    res.render('new_item', { title: 'Post New Item', errors: [], category: category || 'lost' });
});

// Get single item details (for modal)
app.get('/items/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const query = `
            SELECT 
                i.*, 
                u.name as poster_name,
                g.name as guard_name,
                g.phone_number as guard_phone
            FROM items i
            JOIN users u ON i.user_id = u.id
            LEFT JOIN guards g ON i.guard_id = g.id
            WHERE i.id = $1
        `;
        const result = await pool.query(query, [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Item not found' });
        }
        res.json(result.rows[0]);
    } catch (err) {
        console.error("Error fetching item details:", err);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Create New Item
app.post('/items/new', requireAuth, (req, res) => {
    upload(req, res, async (err) => {
        if (err) {
            return res.render('new_item', { title: 'Post New Item', errors: [{ msg: err }], category: req.body.category });
        }

        const { name, description, category, location, custody_status, guard_name, guard_phone } = req.body;
        const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
        const client = await pool.connect();

        try {
            await client.query('BEGIN');
            let guardId = null;

            if (category === 'found' && custody_status === 'with_guard' && guard_name) {
                const guardResult = await client.query(
                    'INSERT INTO guards (name, phone_number) VALUES ($1, $2) RETURNING id',
                    [guard_name, guard_phone || null]
                );
                guardId = guardResult.rows[0].id;
            }

            await client.query(
                `INSERT INTO items (user_id, name, description, category, location, image_url, custody_status, guard_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                [req.session.userId, name, description, category, location, imageUrl, (category === 'found' ? custody_status : null), guardId]
            );

            await client.query('COMMIT');
            res.redirect('/items');
        } catch (e) {
            await client.query('ROLLBACK');
            console.error(e);
            res.render('new_item', { title: 'Post New Item', errors: [{ msg: 'Error adding item. Please try again.' }], category: req.body.category });
        } finally {
            client.release();
        }
    });
});

// Claim/Found an Item
app.post('/items/:id/claim', requireAuth, async (req, res) => {
    const itemId = req.params.id;
    const claimerId = req.session.userId;
    const { finder_phone } = req.body; // Phone number of the person who found a "lost" item.

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Update the claimer's phone number if provided
        if (finder_phone) {
            await client.query('UPDATE users SET phone_number = $1 WHERE id = $2 AND phone_number IS NULL', [finder_phone, claimerId]);
        }

        const itemResult = await client.query('SELECT * FROM items WHERE id = $1 FOR UPDATE', [itemId]);
        if (itemResult.rows.length === 0) {
            return res.status(404).send('Item not found.');
        }
        const item = itemResult.rows[0];

        if (item.is_claimed) {
            return res.status(400).send('Item already claimed.');
        }
        if (item.user_id === claimerId) {
            return res.status(403).send('You cannot interact with an item you posted.');
        }

        await client.query(
            'UPDATE items SET is_claimed = TRUE, claimed_by = $1 WHERE id = $2',
            [claimerId, itemId]
        );

        const ownerResult = await client.query('SELECT u.email, u.name FROM users u WHERE u.id = $1', [item.user_id]);
        const claimerResult = await client.query('SELECT name, phone_number FROM users WHERE id = $1', [claimerId]);

        if (ownerResult.rows.length > 0 && claimerResult.rows.length > 0) {
            const owner = ownerResult.rows[0];
            const claimer = claimerResult.rows[0];
            // Use the newly submitted phone number if it's a "lost" item interaction, otherwise use the claimer's stored number.
            const contactPhone = item.category === 'lost' ? finder_phone : (claimer.phone_number || 'Not provided');
            
            sendClaimNotification(owner.email, owner.name, claimer.name, contactPhone, item.name, item.category);
        }

        await client.query('COMMIT');
        res.redirect('/items');
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).send('Error processing claim.');
    } finally {
        client.release();
    }
});


// --- ADMIN ROUTES ---
app.get('/admin', requireAuth, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                i.*, 
                u.name as poster_name,
                c.name as claimer_name
            FROM items i
            JOIN users u ON i.user_id = u.id
            LEFT JOIN users c ON i.claimed_by = c.id
            ORDER BY i.created_at DESC
        `);
        res.render('admin', { title: 'Admin Dashboard', items: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error fetching items for admin dashboard.');
    }
});

app.post('/admin/items/:id/delete', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        await pool.query('DELETE FROM items WHERE id = $1', [id]);
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error deleting item.');
    }
});


// --- SERVER START ---
app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
});
