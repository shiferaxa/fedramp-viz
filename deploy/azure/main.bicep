// fedramp-viz on Azure App Service: one Linux web app with a system assigned
// identity that holds Reader on the scanned subscription, Entra ID sign in in
// front of everything (App Service authentication), HTTPS and TLS 1.2 only.
// Deployed at subscription scope so the resource group and the Reader role
// assignment land in the same run. See README.md next to this file.
targetScope = 'subscription'

@description('Resource group that holds the dashboard')
param resourceGroupName string = 'fedramp-viz-rg'

@description('Region for the plan and the app')
param location string = 'eastus2'

@description('Web app name, also the default hostname (<name>.azurewebsites.net)')
param appName string = 'fedramp-viz-app'

@description('App Service plan name (B1 Linux)')
param planName string = 'fedramp-viz-asp'

@description('Client id of the Entra app registration used for sign in')
param authClientId string

@secure()
@description('Client secret of that app registration')
param authClientSecret string

@description('Subscription ids the live scan covers, comma separated. Defaults to the deployment subscription. The app identity needs Reader on each.')
param scanSubscriptions string = subscription().subscriptionId

@description('Tags applied to every resource')
param tags object = {
  service: 'fedramp-viz'
}

var readerRoleId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

module app 'app.bicep' = {
  name: 'fedramp-viz-app'
  scope: rg
  params: {
    location: location
    appName: appName
    planName: planName
    authClientId: authClientId
    authClientSecret: authClientSecret
    scanSubscriptions: scanSubscriptions
    tags: tags
  }
}

// Reader on the deployment subscription for the app's managed identity. Other
// subscriptions listed in scanSubscriptions need the same assignment made there.
resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, appName, readerRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', readerRoleId)
    principalId: app.outputs.principalId
    principalType: 'ServicePrincipal'
    description: 'fedramp-viz read only inventory scan'
  }
}

output hostname string = app.outputs.hostname
output principalId string = app.outputs.principalId
