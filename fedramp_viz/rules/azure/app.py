"""App Service (web apps, function apps and their deployment slots) checks.

Slots carry their own httpsOnly, siteConfig, identity and network settings, so
they are checked as resources in their own right.
"""

from __future__ import annotations

from ...models import ImpactLevel, Resource, Severity, failed, manual, passed
from .. import rule
from ._helpers import has_managed_identity, tls_at_least_12, truthy

T = ["microsoft.web/sites", "microsoft.web/sites/slots"]


@rule("AZ-APP-001", "App Service enforces HTTPS", controls=["SC-8", "SC-8(1)"], resource_types=T, severity=Severity.HIGH,
      remediation="az webapp update -g <rg> -n <name> --https-only true")
def https_only(res: Resource):
    """HTTP requests must be redirected so no session ever runs in plain text."""
    v = res.prop("httpsOnly")
    return passed("HTTPS only") if truthy(v) else failed("HTTP is accepted", httpsOnly=v)


@rule("AZ-APP-002", "App Service minimum TLS is 1.2", controls=["SC-8(1)", "SC-13"], resource_types=T, severity=Severity.MEDIUM,
      remediation="az webapp config set -g <rg> -n <name> --min-tls-version 1.2")
def min_tls(res: Resource):
    """Resource Graph exports siteConfig with every value null (the real values live in the site's config/web resource), so a missing or null minTlsVersion asks for a manual look instead of failing."""
    cfg = res.prop("siteConfig")
    v = cfg.get("minTlsVersion") if isinstance(cfg, dict) else None
    if v in (None, ""):
        return manual("siteConfig.minTlsVersion is not populated in the export; check it with az webapp config show --query minTlsVersion", minTlsVersion=v)
    return passed(f"Minimum TLS {v}") if tls_at_least_12(v) else failed(f"Minimum TLS is {v}", minTlsVersion=v)


@rule("AZ-APP-003", "App Service has a managed identity", controls=["IA-5(7)", "IA-5"], resource_types=T, severity=Severity.LOW,
      min_level=ImpactLevel.MODERATE,
      remediation="az webapp identity assign -g <rg> -n <name>, then replace connection string secrets with identity based access.")
def managed_identity(res: Resource):
    """Without an identity the app needs static secrets in settings or code, which is what IA-5(7) prohibits."""
    return passed("Managed identity assigned", identity=res.identity.get("type")) if has_managed_identity(res) else failed("No managed identity", identity=res.identity.get("type"))


@rule("AZ-APP-004", "App Service is not directly exposed to the internet", controls=["SC-7", "SC-7(3)"], resource_types=T, severity=Severity.LOW,
      min_level=ImpactLevel.HIGH,
      remediation="Put the app behind Application Gateway with WAF or Front Door Premium, restrict access with access restrictions or private endpoints, and set publicNetworkAccess to Disabled.")
def public_access(res: Resource):
    """A public app is legitimate when it sits behind a managed access point (WAF); the inventory cannot tell, so an open app is a manual review."""
    v = res.prop("publicNetworkAccess")
    if isinstance(v, str) and v.lower() == "disabled":
        return passed("Public network access disabled")
    return manual("App is publicly reachable; confirm it is fronted by a WAF or gateway that is the managed access point", publicNetworkAccess=v)
