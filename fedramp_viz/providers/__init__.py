"""Inventory providers. Each returns a list of normalized Resource objects."""

from .base import Provider
from .file import FileProvider

__all__ = ["Provider", "FileProvider", "get_provider"]


def get_provider(source: str, **kwargs) -> Provider:
    """`source` is 'azure' for a live query, or a path to an exported JSON file."""
    if source == "azure":
        from .azure import AzureProvider

        return AzureProvider(**kwargs)
    return FileProvider(source)
