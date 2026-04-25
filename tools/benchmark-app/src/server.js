const express = require('express');
const cookieParser = require('cookie-parser');
const { createRepositories } = require('./store/repositories');
const { attachCurrentUser } = require('./middleware/auth');
const { createDocumentRouter } = require('./routes/documents');
const { createRefundRouter } = require('./routes/refunds');
const { createRoleRouter } = require('./routes/roles');
const { createIntegrationRouter } = require('./routes/integrations');
const { createReportRouter } = require('./routes/reports');
const { createProfileRouter } = require('./routes/profile');
const { createImportRouter } = require('./routes/imports');

function createApp() {
  const app = express();
  const repositories = createRepositories();

  app.use(express.json({ limit: '1mb' }));
  app.use(cookieParser());
  app.use(attachCurrentUser(repositories.users));

  app.get('/health', (_req, res) => {
    res.json({ ok: true, service: 'owlvex-benchmark-app' });
  });

  app.use('/documents', createDocumentRouter(repositories));
  app.use('/refunds', createRefundRouter(repositories));
  app.use('/users', createRoleRouter(repositories));
  app.use('/integrations', createIntegrationRouter(repositories));
  app.use('/reports', createReportRouter(repositories));
  app.use('/profile', createProfileRouter(repositories));
  app.use('/imports', createImportRouter(repositories));

  return app;
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  createApp().listen(port, () => {
    console.log(`benchmark app listening on ${port}`);
  });
}

module.exports = { createApp };
