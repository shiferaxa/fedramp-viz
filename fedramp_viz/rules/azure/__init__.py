"""Azure rules. Each module registers itself on import."""

from . import aks, app, compute, data, general, keyvault, logging, network, sql, storage  # noqa: F401
