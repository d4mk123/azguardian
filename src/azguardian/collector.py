import json
from pathlib import Path
from .models import NSGListResult, FlowLogListResult, NetworkSecurityGroup, FlowLog


def collect_from_file(path: str | Path) -> list[NetworkSecurityGroup]:
    """
    Load NSGs from a JSON file exported via:
        az network nsg list -o json
    """
    with open(path) as f:
        data = json.load(f)

    if isinstance(data, list):
        data = {'value': data}

    result = NSGListResult.model_validate(data)
    return result.value


def collect_from_azure(subscription_id: str) -> list[NetworkSecurityGroup]:
    """
    Load NSGs live from an Azure subscription.
    Requires az login or environment credentials.
    """
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.network import NetworkManagementClient

    credential = DefaultAzureCredential()
    client = NetworkManagementClient(credential, subscription_id)

    raw_nsgs = list(client.network_security_groups.list_all())
    nsg_dicts = [nsg.as_dict() for nsg in raw_nsgs]
    return NSGListResult.model_validate({'value': nsg_dicts}).value


def collect_flow_logs_from_file(path: str | Path) -> list[FlowLog]:
    with open(path) as f:
        data = json.load(f)

    if isinstance(data, list):
        data = {'value': data}

    result = FlowLogListResult.model_validate(data)
    return result.value