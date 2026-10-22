// PHP2Shell Exposure Accelerator: deploy-your-own infrastructure
// Deploys into your own subscription: App Service plan, checker API, portal, managed identities,
// role assignments, and (optionally) a new Azure AI Foundry account + project + model deployment.
targetScope = 'resourceGroup'

@description('Short prefix for resource names (lowercase, 3-10 chars).')
@minLength(3)
@maxLength(10)
param prefix string = 'php2shell'

@description('Azure region for App Service resources.')
param location string = resourceGroup().location

@description('App Service plan SKU. B1 is sufficient; avoid Premium in governed subscriptions if cost policies apply.')
@allowed([ 'B1', 'B2', 'B3', 'S1', 'P0v3', 'P1v3' ])
param appServiceSku string = 'B1'

@description('Create a new Foundry account, project and model deployment. If false, supply existingProjectEndpoint and existingFoundryAccountId.')
param createFoundry bool = true

@description('Region for the new Foundry account (must offer the chosen model).')
param foundryLocation string = location

@description('Model to deploy when createFoundry = true.')
param modelName string = 'gpt-4.1-mini'
param modelVersion string = ''
param modelFormat string = 'OpenAI'
param modelSkuName string = 'GlobalStandard'
param modelCapacity int = 50

@description('Existing Foundry project endpoint (https://<account>.services.ai.azure.com/api/projects/<project>) when createFoundry = false.')
param existingProjectEndpoint string = ''

@description('Resource ID of the existing Foundry (AIServices) account when createFoundry = false.')
param existingFoundryAccountId string = ''

@description('Model deployment name to use for the agents when createFoundry = false.')
param existingModelDeployment string = ''

@description('Entra ID tenant used for portal sign-in (defaults to the deployment tenant).')
param tenantId string = subscription().tenantId

@description('Client ID of the Entra app registration for portal sign-in (created by deploy.ps1). Sign-in is mandatory.')
@minLength(36)
param authClientId string

@description('Client ID of the Entra app registration that protects the checker API (created by deploy.ps1). Authentication is mandatory.')
@minLength(36)
param checkerAuthClientId string

@description('Subscription IDs the checker may inventory. Requests for any other subscription are refused server-side.')
@minLength(1)
param allowedSubscriptionIds array

@description('Additional managed identity object IDs allowed to call the checker API (e.g. an existing Foundry project identity).')
param extraCheckerPrincipalIds array = []

@description('Tags applied to all resources.')
param tags object = { solution: 'php2shell-exposure-accelerator' }

var suffix = toLower(substring(uniqueString(resourceGroup().id, prefix), 0, 5))
var planName = '${prefix}-plan-${suffix}'
var apiName = '${prefix}-checker-${suffix}'
var portalName = '${prefix}-portal-${suffix}'
var foundryName = '${prefix}-foundry-${suffix}'
var projectName = '${prefix}-project'
var modelDeploymentName = createFoundry ? modelName : existingModelDeployment

// Built-in role definition IDs
var roleFoundryUser = '53ca6127-db72-4b80-b1b0-d745d6d5456d'
var roleFoundryAgentConsumer = 'eed3b665-ab3a-47b6-8f48-c9382fb1dad6'

// ---------------- Foundry (optional) ----------------
resource foundry 'Microsoft.CognitiveServices/accounts@2025-06-01' = if (createFoundry) {
  name: foundryName
  location: foundryLocation
  tags: tags
  kind: 'AIServices'
  sku: { name: 'S0' }
  identity: { type: 'SystemAssigned' }
  properties: {
    customSubDomainName: foundryName
    allowProjectManagement: true
    publicNetworkAccess: 'Enabled'
    disableLocalAuth: true
  }
}

resource project 'Microsoft.CognitiveServices/accounts/projects@2025-06-01' = if (createFoundry) {
  parent: foundry
  name: projectName
  location: foundryLocation
  tags: tags
  identity: { type: 'SystemAssigned' }
  properties: {
    displayName: 'PHP2Shell Exposure Accelerator'
    description: 'Agents for defensive PHP2Shell exposure checks'
  }
}

resource modelDeployment 'Microsoft.CognitiveServices/accounts/deployments@2025-06-01' = if (createFoundry) {
  parent: foundry
  name: modelName
  sku: { name: modelSkuName, capacity: modelCapacity }
  properties: {
    model: empty(modelVersion) ? { format: modelFormat, name: modelName } : { format: modelFormat, name: modelName, version: modelVersion }
  }
  dependsOn: [ project ]
}

var projectEndpoint = createFoundry ? 'https://${foundryName}.services.ai.azure.com/api/projects/${projectName}' : existingProjectEndpoint

// ---------------- App Service ----------------
resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: planName
  location: location
  tags: tags
  kind: 'linux'
  sku: { name: appServiceSku }
  properties: { reserved: true }
}

resource api 'Microsoft.Web/sites@2024-04-01' = {
  name: apiName
  location: location
  tags: tags
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.12'
      alwaysOn: true
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      appCommandLine: 'gunicorn -w 2 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000 app:app --timeout 120'
      appSettings: [
        { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'true' }
        { name: 'WEBSITES_PORT', value: '8000' }
        { name: 'PUBLIC_BASE_URL', value: 'https://${apiName}.azurewebsites.net' }
        { name: 'ALLOWED_SUBSCRIPTION_IDS', value: join(allowedSubscriptionIds, ',') }
      ]
    }
  }
}

resource portal 'Microsoft.Web/sites@2024-04-01' = {
  name: portalName
  location: location
  tags: tags
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.12'
      alwaysOn: true
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      appCommandLine: 'gunicorn -w 2 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000 app:app --timeout 300'
      appSettings: [
        { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'true' }
        { name: 'WEBSITES_PORT', value: '8000' }
        { name: 'PROJECT_ENDPOINT', value: projectEndpoint }
        { name: 'CHECKER_API', value: 'https://${apiName}.azurewebsites.net' }
        { name: 'DEFAULT_SUBSCRIPTION_ID', value: allowedSubscriptionIds[0] }
        { name: 'ALLOWED_SUBSCRIPTION_IDS', value: join(allowedSubscriptionIds, ',') }
        { name: 'AGENT_PREFIX', value: prefix }
        { name: 'CHECKER_AUDIENCE', value: 'api://${checkerAuthClientId}' }
      ]
    }
  }
}

// Checker API accepts only tokens issued to the portal and Foundry managed identities
var checkerCallers = concat(
  [ portal.identity.principalId ],
  createFoundry ? [ foundry!.identity.principalId, project!.identity.principalId ] : [],
  extraCheckerPrincipalIds)

resource apiAuth 'Microsoft.Web/sites/config@2024-04-01' = {
  parent: api
  name: 'authsettingsV2'
  properties: {
    platform: { enabled: true }
    globalValidation: {
      requireAuthentication: true
      unauthenticatedClientAction: 'Return401'
      excludedPaths: [ '/healthz', '/openapi.json', '/docs' ]
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          clientId: checkerAuthClientId
          openIdIssuer: 'https://sts.windows.net/${tenantId}/'
        }
        validation: {
          allowedAudiences: [ 'api://${checkerAuthClientId}', checkerAuthClientId ]
          defaultAuthorizationPolicy: {
            allowedPrincipals: { identities: checkerCallers }
          }
        }
      }
    }
  }
}

// Entra ID sign-in on the portal (App Service Authentication / Easy Auth). Only users or groups assigned to the
// portal's enterprise application can sign in (deploy.ps1 sets appRoleAssignmentRequired).
resource portalAuth 'Microsoft.Web/sites/config@2024-04-01' = {
  parent: portal
  name: 'authsettingsV2'
  properties: {
    platform: { enabled: true }
    globalValidation: {
      requireAuthentication: true
      unauthenticatedClientAction: 'RedirectToLoginPage'
      redirectToProvider: 'azureactivedirectory'
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          clientId: authClientId
          openIdIssuer: '${environment().authentication.loginEndpoint}${tenantId}/v2.0'
        }
        validation: {
          allowedAudiences: [ 'api://${authClientId}', authClientId ]
        }
      }
    }
    login: { tokenStore: { enabled: true } }
  }
}

// ---------------- RBAC: portal identity -> Foundry ----------------
resource portalFoundryUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (createFoundry) {
  name: guid(foundryName, portalName, roleFoundryUser)
  scope: foundry
  properties: {
    principalId: portal.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleFoundryUser)
  }
}

resource portalAgentConsumer 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (createFoundry) {
  name: guid(foundryName, portalName, roleFoundryAgentConsumer)
  scope: foundry
  properties: {
    principalId: portal.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleFoundryAgentConsumer)
  }
}

output apiName string = api.name
output apiId string = api.id
output portalId string = portal.id
output planId string = plan.id
output portalName string = portal.name
output apiUrl string = 'https://${api.properties.defaultHostName}'
output portalUrl string = 'https://${portal.properties.defaultHostName}'
output apiPrincipalId string = api.identity.principalId
output portalPrincipalId string = portal.identity.principalId
output projectEndpoint string = projectEndpoint
output modelDeployment string = modelDeploymentName
output foundryAccountId string = createFoundry ? foundry.id : existingFoundryAccountId
output checkerAudience string = 'api://${checkerAuthClientId}'
