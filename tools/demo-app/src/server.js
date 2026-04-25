const express = require('express');
const cookieParser = require('cookie-parser');
const { attachSession } = require('./middleware/auth');
const { requireCsrf } = require('./middleware/csrf');
const documentRoutes = require('./routes/documents');
const browserRoutes = require('./routes/browser');
const integrationRoutes = require('./routes/integrations');
const uploadRoutes = require('./routes/uploads');
const searchRoutes = require('./routes/search');
const authRoutes = require('./routes/auth');
const logRoutes = require('./routes/logs');
const filmingRoutes = require('./routes/filming');

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(attachSession);

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'owlvex-demo-app' });
});

app.use('/documents', documentRoutes);
app.use('/browser', browserRoutes);
app.use('/integrations', integrationRoutes);
app.use('/uploads', uploadRoutes);
app.use('/search', searchRoutes);
app.use('/auth', authRoutes);
app.use('/logs', logRoutes);
app.use('/filming', filmingRoutes);

app.post('/browser/profile-safe', requireCsrf, (req, res) => {
  res.json({
    updated: true,
    displayName: req.body.displayName,
  });
});

app.listen(3030, () => {
  console.log('Owlvex demo app listening on http://localhost:3030');
});
