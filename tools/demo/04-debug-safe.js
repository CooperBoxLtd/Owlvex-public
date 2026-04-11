// Demo fixture 04 — Debug mode correctly guarded
//
// Structurally identical to 03 except for the if-guard.
// Owlvex is silent. Same rule, different structure.

const express = require('express');
const app = express();

const port = process.env.NODE_ENV === 'production' ? 80 : 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.get('/api/health', (req, res) => res.json({ ok: true }));

// FIXED: debug mode guarded
if (process.env.NODE_ENV !== 'production') {
    app.set('debug', true);
}

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
