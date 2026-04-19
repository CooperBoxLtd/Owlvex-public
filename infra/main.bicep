// ============================================================
// Owlvex — Azure production infrastructure
//
// Resources:
//   - Resource group (created by deploy.sh before this runs)
//   - Azure Container Registry (ACR)
//   - Azure Database for PostgreSQL Flexible Server
//   - Azure Key Vault
//   - Log Analytics workspace
//   - Azure App Service Plan
//   - Azure Web App for Containers
//
// Principles:
//   - Backend only (licence, billing, prompt delivery, metadata)
//   - No source code ever reaches these resources for scanning
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

@description('PostgreSQL admin username')
param postgresAdminUser string = 'owlvex'

@secure()
@description('PostgreSQL admin password')
param postgresAdminPassword string

@description('PostgreSQL database name')
param postgresDbName string = 'owlvex'

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
param stripePriceDeveloperAnnual string = ''
param stripePriceTeamMonthly string = ''
param stripePriceTeamAnnual string = ''
param fromEmail string = 'noreply@owlvex.io'

var acrName = '${prefix}registry'
var appServicePlanName = '${prefix}-plan'
var webAppName = '${prefix}-api'
var acrLoginServer = acr.properties.loginServer
var dbHost = postgres.properties.fullyQualifiedDomainName
var dbUrl = 'postgresql+asyncpg://${postgresAdminUser}:${postgresAdminPassword}@${dbHost}:5432/${postgresDbName}?ssl=require'

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: acrName
  location: location
  sku: { name: 'Basic' }
  properties: {
    adminUserEnabled: true
  }
  tags: { environment: environment }
}

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: '${prefix}-logs'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
  tags: { environment: environment }
}

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

resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2023-06-01-preview' = {
  name: '${prefix}-db'
  location: location
  sku: {
    name: 'Standard_B1ms'
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

resource postgresFirewallAzureServices 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2023-06-01-preview' = {
  parent: postgres
  name: 'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: appServicePlanName
  location: location
  sku: {
    name: 'B1'
    tier: 'Basic'
    size: 'B1'
    family: 'B'
    capacity: 1
  }
  kind: 'linux'
  properties: {
    reserved: true
  }
  tags: { environment: environment }
}

resource webApp 'Microsoft.Web/sites@2023-12-01' = {
  name: webAppName
  location: location
  kind: 'app,linux,container'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'DOCKER|${acrLoginServer}/owlvex-api:${imageTag}'
      appSettings: [
        {
          name: 'DOCKER_REGISTRY_SERVER_URL'
          value: 'https://${acrLoginServer}'
        }
        {
          name: 'DOCKER_REGISTRY_SERVER_USERNAME'
          value: acr.listCredentials().username
        }
        {
          name: 'DOCKER_REGISTRY_SERVER_PASSWORD'
          value: acr.listCredentials().passwords[0].value
        }
        {
          name: 'WEBSITES_PORT'
          value: '8000'
        }
        {
          name: 'WEBSITES_ENABLE_APP_SERVICE_STORAGE'
          value: 'false'
        }
        {
          name: 'DATABASE_URL'
          value: dbUrl
        }
        {
          name: 'SECRET_KEY'
          value: secretKey
        }
        {
          name: 'ADMIN_KEY'
          value: adminKey
        }
        {
          name: 'STRIPE_SECRET_KEY'
          value: stripeSecretKey
        }
        {
          name: 'STRIPE_WEBHOOK_SECRET'
          value: stripeWebhookSecret
        }
        {
          name: 'SENDGRID_API_KEY'
          value: sendgridApiKey
        }
        {
          name: 'STRIPE_PRICE_DEVELOPER_MONTHLY'
          value: stripePriceDeveloperMonthly
        }
        {
          name: 'STRIPE_PRICE_DEVELOPER_ANNUAL'
          value: stripePriceDeveloperAnnual
        }
        {
          name: 'STRIPE_PRICE_TEAM_MONTHLY'
          value: stripePriceTeamMonthly
        }
        {
          name: 'STRIPE_PRICE_TEAM_ANNUAL'
          value: stripePriceTeamAnnual
        }
        {
          name: 'FROM_EMAIL'
          value: fromEmail
        }
        {
          name: 'ENVIRONMENT'
          value: environment
        }
      ]
      healthCheckPath: '/health'
      alwaysOn: true
      acrUseManagedIdentityCreds: false
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      http20Enabled: true
    }
  }
  tags: { environment: environment }
}

output apiUrl string = 'https://${webApp.properties.defaultHostName}'
output acrLoginServer string = acrLoginServer
output postgresHost string = dbHost
output keyVaultName string = keyVault.name
output webAppName string = webApp.name
