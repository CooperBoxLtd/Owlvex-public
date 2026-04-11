// ============================================================
// Owlvex — Azure production infrastructure
//
// Resources:
//   - Resource group (created by deploy.sh before this runs)
//   - Azure Container Registry (ACR)
//   - Azure Database for PostgreSQL Flexible Server
//   - Azure Key Vault
//   - Log Analytics workspace
//   - Azure Container Apps environment + app
//
// Principles:
//   - Backend only (licence, billing, prompt delivery)
//   - No source code ever reaches these resources
//   - Deterministic engine runs locally in the extension/CLI
// ============================================================

@description('Environment tag — prod only here')
param environment string = 'production'

@description('Azure region')
param location string = resourceGroup().location

@description('Short prefix used in all resource names')
param prefix string = 'owlvex'

@description('Container image tag to deploy')
param imageTag string = 'latest'

// ── Postgres ──────────────────────────────────────────────────────────────

@description('PostgreSQL admin username')
param postgresAdminUser string = 'owlvex'

@secure()
@description('PostgreSQL admin password')
param postgresAdminPassword string

@description('PostgreSQL database name')
param postgresDbName string = 'owlvex'

// ── App secrets (stored in Key Vault, injected at runtime) ────────────────

@secure()
param secretKey string

@secure()
param adminKey string

@secure()
param stripeSecretKey string = ''

@secure()
param stripeWebhookSecret string = ''

@secure()
param sendgridApiKey string = ''

param stripePriceDeveloperMonthly string = ''
param stripePriceDeveloperAnnual string  = ''
param stripePriceTeamMonthly string      = ''
param stripePriceTeamAnnual string       = ''
param fromEmail string                   = 'noreply@owlvex.io'

// ── Container Registry ────────────────────────────────────────────────────

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: '${prefix}registry'
  location: location
  sku: { name: 'Basic' }
  properties: {
    adminUserEnabled: true
  }
  tags: { environment: environment }
}

// ── Log Analytics ─────────────────────────────────────────────────────────

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: '${prefix}-logs'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
  tags: { environment: environment }
}

// ── Key Vault ─────────────────────────────────────────────────────────────

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '${prefix}-kv'
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    softDeleteRetentionInDays: 7
    enabledForTemplateDeployment: false
  }
  tags: { environment: environment }
}

resource kvSecretKey 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'secret-key'
  properties: { value: secretKey }
}

resource kvAdminKey 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'admin-key'
  properties: { value: adminKey }
}

resource kvStripeSecretKey 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'stripe-secret-key'
  properties: { value: stripeSecretKey }
}

resource kvStripeWebhookSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'stripe-webhook-secret'
  properties: { value: stripeWebhookSecret }
}

resource kvSendgridApiKey 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'sendgrid-api-key'
  properties: { value: sendgridApiKey }
}

// ── PostgreSQL Flexible Server ─────────────────────────────────────────────

resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2023-06-01-preview' = {
  name: '${prefix}-db'
  location: location
  sku: {
    name: 'Standard_B1ms'   // 1 vCore, 2GB — sufficient for Phase 1
    tier: 'Burstable'
  }
  properties: {
    administratorLogin: postgresAdminUser
    administratorLoginPassword: postgresAdminPassword
    storage: { storageSizeGB: 32 }
    backup: {
      backupRetentionDays: 7
      geoRedundantBackup: 'Disabled'
    }
    highAvailability: { mode: 'Disabled' }
    version: '16'
  }
  tags: { environment: environment }
}

resource postgresDb 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2023-06-01-preview' = {
  parent: postgres
  name: postgresDbName
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

// Allow Azure Container Apps egress to reach Postgres
// (Container Apps uses managed VNet; allow Azure services is sufficient for Phase 1)
resource postgresFirewallAzureServices 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2023-06-01-preview' = {
  parent: postgres
  name: 'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

// ── Container Apps Environment ────────────────────────────────────────────

resource containerAppsEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${prefix}-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
  tags: { environment: environment }
}

// ── Container App ─────────────────────────────────────────────────────────

var acrLoginServer = acr.properties.loginServer
var dbUrl = 'postgresql+asyncpg://${postgresAdminUser}:${postgresAdminPassword}@${postgres.properties.fullyQualifiedDomainName}:5432/${postgresDbName}?ssl=require'

resource containerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${prefix}-api'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: containerAppsEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8000
        transport: 'http'
        allowInsecure: false
      }
      registries: [
        {
          server: acrLoginServer
          username: acr.listCredentials().username
          passwordSecretRef: 'acr-password'
        }
      ]
      secrets: [
        {
          name: 'acr-password'
          value: acr.listCredentials().passwords[0].value
        }
        { name: 'database-url',             value: dbUrl }
        { name: 'secret-key',               value: secretKey }
        { name: 'admin-key',                value: adminKey }
        { name: 'stripe-secret-key',        value: stripeSecretKey }
        { name: 'stripe-webhook-secret',    value: stripeWebhookSecret }
        { name: 'sendgrid-api-key',         value: sendgridApiKey }
      ]
    }
    template: {
      containers: [
        {
          name: 'api'
          image: '${acrLoginServer}/owlvex-api:${imageTag}'
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            { name: 'DATABASE_URL',                    secretRef: 'database-url' }
            { name: 'SECRET_KEY',                      secretRef: 'secret-key' }
            { name: 'ADMIN_KEY',                       secretRef: 'admin-key' }
            { name: 'STRIPE_SECRET_KEY',               secretRef: 'stripe-secret-key' }
            { name: 'STRIPE_WEBHOOK_SECRET',           secretRef: 'stripe-webhook-secret' }
            { name: 'SENDGRID_API_KEY',                secretRef: 'sendgrid-api-key' }
            { name: 'STRIPE_PRICE_DEVELOPER_MONTHLY',  value: stripePriceDeveloperMonthly }
            { name: 'STRIPE_PRICE_DEVELOPER_ANNUAL',   value: stripePriceDeveloperAnnual }
            { name: 'STRIPE_PRICE_TEAM_MONTHLY',       value: stripePriceTeamMonthly }
            { name: 'STRIPE_PRICE_TEAM_ANNUAL',        value: stripePriceTeamAnnual }
            { name: 'FROM_EMAIL',                      value: fromEmail }
            { name: 'ENVIRONMENT',                     value: 'production' }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 8000
              }
              initialDelaySeconds: 15
              periodSeconds: 20
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/health'
                port: 8000
              }
              initialDelaySeconds: 10
              periodSeconds: 10
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 3
        rules: [
          {
            name: 'http-scaling'
            http: {
              metadata: {
                concurrentRequests: '20'
              }
            }
          }
        ]
      }
    }
  }
  tags: { environment: environment }
}

// ── Outputs ───────────────────────────────────────────────────────────────

output apiUrl string = 'https://${containerApp.properties.configuration.ingress.fqdn}'
output acrLoginServer string = acrLoginServer
output postgresHost string = postgres.properties.fullyQualifiedDomainName
output keyVaultName string = keyVault.name
output containerAppName string = containerApp.name
