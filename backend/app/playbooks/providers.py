"""
Response provider abstraction for actions that would, in a real deployment,
reach an external system (a firewall/EDR/IdP). Per this milestone's explicit
scope, no such integration is implemented yet -- MockResponseProvider is the
only concrete provider, and it never touches the network, the OS, or any
real user/host record. It only records a structured "would have done X"
result. Swapping in a real BlockIPProvider/EndpointIsolationProvider/
IdentityProvider later means implementing this same ResponseProvider
interface -- the playbook engine and action registry never change.
"""
from abc import ABC, abstractmethod
from datetime import datetime


class ProviderError(Exception):
    """Raised by a provider when it fails or times out."""


class ResponseProvider(ABC):
    @abstractmethod
    def execute(self, action: str, parameters: dict) -> dict:
        """Return a JSON-serialisable result dict. Raise ProviderError on failure."""


class MockResponseProvider(ResponseProvider):
    def execute(self, action: str, parameters: dict) -> dict:
        return {
            "mode": "dry_run",
            "action": action,
            "parameters": parameters,
            "result": "simulated_success",
            "message": (
                f"DRY RUN: would have executed '{action}' with {parameters}. "
                "No real-world action was taken (MockResponseProvider)."
            ),
            "simulated_at": datetime.utcnow().isoformat() + "Z",
        }


default_provider = MockResponseProvider()
