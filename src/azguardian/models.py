from enum import StrEnum
from pydantic import BaseModel, ConfigDict, model_validator
from pydantic.alias_generators import to_camel


class SecurityDirection(StrEnum):
    INBOUND = "Inbound"
    OUTBOUND = "Outbound"


class SecurityProtocol(StrEnum):
    TCP = "Tcp"
    UDP = "Udp"
    ASTERISK = "*"
    ICMP = "Icmp"
    ESP = "Esp"
    AH = "Ah"


class SecurityAccess(StrEnum):
    ALLOW = "Allow"
    DENY = "Deny"


class SecurityRule(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    name: str
    priority: int
    direction: SecurityDirection
    access: SecurityAccess
    protocol: SecurityProtocol
    source_address_prefix: str | None = None
    source_port_range: str | None = None
    destination_address_prefix: str | None = None
    destination_port_range: str | None = None
    description: str | None = None

    @model_validator(mode='before')
    @classmethod
    def _flatten_properties(cls, data: dict) -> dict:
        if isinstance(data, dict) and 'properties' in data:
            props = data.pop('properties')
            data.update(props)
        return data


class Subnet(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    id: str
    name: str


class NicAssociation(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    id: str
    name: str


class NetworkSecurityGroup(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    id: str
    name: str
    location: str
    tags: dict[str, str] = {}
    security_rules: list[SecurityRule] = []
    default_security_rules: list[SecurityRule] = []
    subnets: list[Subnet] = []
    network_interfaces: list[NicAssociation] = []

    @model_validator(mode='before')
    @classmethod
    def _flatten_properties(cls, data: dict) -> dict:
        if isinstance(data, dict) and 'properties' in data:
            props = data.pop('properties')
            data.update(props)
        return data


class RetentionPolicy(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    days: int
    enabled: bool


class FlowLog(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    name: str
    target_resource_id: str
    enabled: bool
    retention_policy: RetentionPolicy | None = None

    @model_validator(mode='before')
    @classmethod
    def _flatten_properties(cls, data: dict) -> dict:
        if isinstance(data, dict) and 'properties' in data:
            props = data.pop('properties')
            data.update(props)
        return data


class NSGListResult(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    value: list[NetworkSecurityGroup]


class FlowLogListResult(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    value: list[FlowLog]