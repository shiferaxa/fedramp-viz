// fedramp-viz on Azure App Service: one Linux web app with a system assigned
// identity, Entra ID sign in in front of everything (App Service authentication),
// HTTPS and TLS 1.2 only. Deployed at subscription scope so the resource group
// and the optional Reader role assignment land in the same run.
//
// Two scan modes:
//   * single tenant: the web app's managed identity reads Resource Graph in this
//     tenant (grantReader gives it Reader on this subscription)
//   * several tenants: scanTenants + scanClientId name a multi tenant app whose
//     federated credential trusts the managed identity; its service principal
//     needs Reader in each tenant (deploy.py --onboard does that)
// See README.md next to this file.
targetScope = 'subscription'

@description('Resource group that holds the dashboard')
param resourceGroupName string = 'fedramp-viz-rg'

@description('Region for the plan and the app')
param location string = 'eastus2'

@description('Web app name, also the default hostname (<name>.azurewebsites.net)')
param appName string = 'fedramp-viz-app'

@description('App Service plan name (B1 Linux)')
param planName string = 'fedramp-viz-asp'

@description('Client id of the Entra app registration used for sign in (this tenant)')
param authClientId string

@secure()
@description('Client secret of that app registration')
param authClientSecret string

@description('Subscription ids to limit the scan to, comma separated. Empty scans everything the identity can read.')
param scanSubscriptions string = ''

@description('Tenant ids to scan, comma separated. Empty means this tenant only, through the managed identity.')
param scanTenants string = ''

@description('Client id of the multi tenant scanner app registration (federated to the managed identity). Empty for single tenant mode.')
param scanClientId string = ''

@description('Give the managed identity Reader on this subscription (single tenant mode)')
param grantReader bool = true

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
    scanTenants: scanTenants
    scanClientId: scanClientId
    tags: tags
  }
}

resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (grantReader) {
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
