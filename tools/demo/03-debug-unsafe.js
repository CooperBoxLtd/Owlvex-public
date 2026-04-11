// Demo fixture 03 — Debug mode without production guard
//
// This code is env-aware (references NODE_ENV) but does not guard
// the debug activation. Owlvex SM-002 fires.

const express = require('express');
const app = express();

const port = process.env.NODE_ENV === 'production' ? 80 : 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.get('/api/health', (req, res) => res.json({ ok: true }));

// BUG: debug mode not guarded — active in production
app.set('debug', true);

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
