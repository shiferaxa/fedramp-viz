// Resource group scope: plan, web app, hardening and Entra sign in.
param location string
param appName string
param planName string
param authClientId string
@secure()
param authClientSecret string
param scanSubscriptions string
param scanTenants string
param scanClientId string
param tags object

var subscriptionArgs = empty(scanSubscriptions) ? '' : join(map(split(scanSubscriptions, ','), s => '--subscription ${trim(s)}'), ' ')
var baseSettings = [
  { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'true' }
  { name: 'MICROSOFT_PROVIDER_AUTHENTICATION_SECRET', value: authClientSecret }
  { name: 'WEBSITE_HTTPLOGGING_RETENTION_DAYS', value: '7' }
]
var tenantSettings = empty(scanTenants) ? [] : [ { name: 'FEDRAMP_VIZ_TENANTS', value: scanTenants } ]
var scannerSettings = empty(scanClientId) ? [] : [ { name: 'FEDRAMP_VIZ_SCAN_CLIENT_ID', value: scanClientId } ]

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: planName
  location: location
  tags: tags
  kind: 'linux'
  sku: {
    name: 'B1'
    tier: 'Basic'
  }
  properties: {
    reserved: true
  }
}

resource site 'Microsoft.Web/sites@2023-12-01' = {
  name: appName
  location: location
  tags: tags
  kind: 'app,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    clientAffinityEnabled: false
    publicNetworkAccess: 'Enabled'
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.12'
      alwaysOn: true
      http20Enabled: true
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      ftpsState: 'Disabled'
      // The scan runs at start (managed identity, or the federated scanner app per tenant); a rescan re-reads Resource Graph.
      appCommandLine: trim('python -m fedramp_viz.cli serve --source azure --host 0.0.0.0 --port 8000 ${subscriptionArgs}')
      appSettings: concat(baseSettings, tenantSettings, scannerSettings)
    }
  }
}

// App Service authentication: every request, including /api, must carry an Entra
// session for this tenant. Unauthenticated browsers are redirected to sign in.
resource auth 'Microsoft.Web/sites/config@2023-12-01' = {
  parent: site
  name: 'authsettingsV2'
  properties: {
    platform: {
      enabled: true
      runtimeVersion: '~1'
    }
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
          clientSecretSettingName: 'MICROSOFT_PROVIDER_AUTHENTICATION_SECRET'
          openIdIssuer: '${environment().authentication.loginEndpoint}${tenant().tenantId}/v2.0'
        }
        validation: {
          allowedAudiences: [
            authClientId
            'api://${authClientId}'
          ]
        }
      }
    }
    login: {
      tokenStore: {
        enabled: true
      }
    }
    httpSettings: {
      requireHttps: true
    }
  }
}

output hostname string = site.properties.defaultHostName
output principalId string = site.identity.principalId
