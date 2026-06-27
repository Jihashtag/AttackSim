"""Target abstraction package."""
from .model import (  # noqa: F401
    Target, TargetError, resolve, resolve_from_dict, parse_hosts,
    REPO, URL, CREDS, HOSTPORT, LOCAL, CLOUD, NETRANGE,
)
