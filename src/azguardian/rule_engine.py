from pydantic import BaseModel
from typing import Literal

from .models import NetworkSecurityGroup, SecurityAccess, SecurityDirection, SecurityProtocol, FlowLog
import ipaddress

def _is_specific_ip(source: str | None) -> bool:
    if source is None:
        return False
    try:
        ipaddress.ip_network(source, strict=False)
        return True
    except ValueError:
        return False
class CheckResult(BaseModel):
    control_id: str
    status: Literal["pass", "fail", "manual"]
    severity: str
    nsg_name: str
    rule_name: str | None = None
    evidence: str 

# Helper functions

def _is_internet(source: str | None) -> bool:
    if source in ["*", "Internet", "0.0.0.0/0"]:
        return True
    return False

def _ports_intersect(rule_port: str | None, target_ports: set[int]) -> bool:
    if rule_port == "*":
        return True
    if rule_port is None:
        return True
    ports = rule_port.split(",")
    for port in ports:
        if "-" in port:
            start, end = map(int, port.split("-"))
            if any(p in target_ports for p in range(start, end + 1) ):
                return True
        else:
            if int(port) in target_ports:
                return True
    return False

def _port_sensitivity(port_range: str | None, protocol: SecurityProtocol) -> str:
    if port_range == "*":
        return "critical"

    if protocol in (SecurityProtocol.UDP, SecurityProtocol.ASTERISK):
        sensitive_udp = {53, 123, 161, 389, 1900}
        if _ports_intersect(port_range, sensitive_udp):
            return "high"

    if protocol in (SecurityProtocol.TCP, SecurityProtocol.ASTERISK):
        if _ports_intersect(port_range, {3389}):
            return "critical"
        if _ports_intersect(port_range, {22}):
            return "critical"
        if _ports_intersect(port_range, {80, 443}):
            return "medium"

    return "low"


def _compute_severity(cis_level: int, internet_exposed: bool, sensitivity: str) -> str:
    if not internet_exposed:
        return "Low"
    if sensitivity == "critical":
        return "Critical"
    if sensitivity == "high":
        return "High"
    if sensitivity == "medium":
        return "Medium"
    return "Medium"

def _check_internet_exposed(
    nsgs: list[NetworkSecurityGroup],
    target_ports: set[int],
    protocol: SecurityProtocol,
    control_id: str,
    severity: str,
    description: str,
) -> list[CheckResult]:
    results: list[CheckResult] = []
    for nsg in nsgs:
        found = False
        for rule in nsg.security_rules:
            if (rule.direction == SecurityDirection.INBOUND and
                rule.access == SecurityAccess.ALLOW and
                rule.protocol in [protocol, SecurityProtocol.ASTERISK] and
                _is_internet(rule.source_address_prefix) and _ports_intersect(rule.destination_port_range, target_ports)):
                results.append(CheckResult(
                    control_id=control_id,
                    status="fail",
                    severity=severity,
                    nsg_name=nsg.name,
                    rule_name=rule.name,
                    evidence=f"NSG '{nsg.name}' has an inbound rule '{rule.name}' allowing {protocol} traffic from the internet to ports {rule.destination_port_range}. {description}"
                ))
                found = True
        if not found:
            results.append(CheckResult(
                control_id=control_id,
                status="pass",
                severity=severity,
                nsg_name=nsg.name,
                evidence=f"NSG '{nsg.name}' has no inbound rules allowing {protocol} traffic from the internet to ports {target_ports}. {description}"
            ))
    return results
    
def check_rdp_internet(nsgs):
    return _check_internet_exposed(
        nsgs, {3389}, SecurityProtocol.TCP, "7.1",
        _compute_severity(1, True, _port_sensitivity("3389", SecurityProtocol.TCP)),
        "RDP exposed to Internet"
    )

def check_ssh_internet(nsgs):
    return _check_internet_exposed(
        nsgs, {22}, SecurityProtocol.TCP, "7.2",
        _compute_severity(1, True, _port_sensitivity("22", SecurityProtocol.TCP)),
        "SSH exposed to Internet"
    )

def check_udp_internet(nsgs):
    severity = _compute_severity(1, True, _port_sensitivity("53", SecurityProtocol.UDP))
    return _check_internet_exposed(nsgs, {53,123,161,389,1900}, SecurityProtocol.UDP, "7.3", severity, "Sensitive UDP ports exposed to Internet")

def check_https_internet(nsgs):
    severity = _compute_severity(1, True, _port_sensitivity("80", SecurityProtocol.TCP))
    return _check_internet_exposed(nsgs, {80,443}, SecurityProtocol.TCP, "7.4", severity, "HTTP/S exposed to Internet")


def check_any_any_rule(nsgs):
    results: list[CheckResult] = []
    for nsg in nsgs:
        found = False
        for rule in nsg.security_rules:
            if (rule.direction == SecurityDirection.INBOUND and
                rule.access == SecurityAccess.ALLOW and
                rule.protocol == SecurityProtocol.ASTERISK and
                rule.destination_port_range == "*" and
                rule.source_address_prefix == "*"):
                results.append(CheckResult(
                    control_id="N/A",
                    status="fail",
                    severity="Critical",
                    nsg_name=nsg.name,
                    rule_name=rule.name,
                    evidence=f"NSG '{nsg.name}' has an inbound rule '{rule.name}' allowing all traffic from the internet to all ports. This is a security risk."
                ))
                found = True
        if not found:
            results.append(CheckResult(
                control_id="N/A",
                status="pass",
                severity="Critical",
                nsg_name=nsg.name,
                evidence=f"NSG '{nsg.name}' has no inbound rules allowing all traffic from the internet to all ports."
            ))
    return results

def check_missing_deny_all(nsgs):
    results: list[CheckResult] = []
    for nsg in nsgs:
        found = False
        for rule in nsg.security_rules:
            if (rule.direction == SecurityDirection.INBOUND and
                rule.access == SecurityAccess.DENY and
                rule.protocol == SecurityProtocol.ASTERISK and
                rule.destination_port_range == "*" and
                rule.source_address_prefix == "*"):
                found = True
                break
        if found:
            results.append(CheckResult(
                control_id="N/A",
                status="pass",
                severity="High",
                nsg_name=nsg.name,
                evidence=f"NSG '{nsg.name}' has a custom deny all inbound rule."
            ))    
        if not found:
            results.append(CheckResult(
                control_id="N/A",
                status="fail",
                severity="High",
                nsg_name=nsg.name,
                evidence=f"NSG '{nsg.name}' does not have a custom deny all inbound rule. This is a security risk."
            ))
    return results

# Note: This only flags NSGs with empty subnet lists.
# Subnets with no NSG at all (orphaned subnets) cannot be detected
# without VNet data — see Day 17 for VNet collector

def check_subnet_association(nsgs):
    results: list[CheckResult] = []
    for nsg in nsgs:
        if len(nsg.subnets) == 0:
            results.append(CheckResult(
                control_id="7.11",
                status="fail",
                severity="Medium",
                nsg_name=nsg.name,
                evidence=f"NSG '{nsg.name}' is not associated with any subnets. This may indicate that the NSG is not being used."
            ))
        else:
            results.append(CheckResult(
                control_id="7.11",
                status="pass",
                severity="Medium",
                nsg_name=nsg.name,
                evidence=f"NSG '{nsg.name}' is associated with {len(nsg.subnets)} subnets."
            ))
    return results

def check_overly_broad_service_tags(nsgs: list[NetworkSecurityGroup]) -> list[CheckResult]:
    results: list[CheckResult] = []
    for nsg in nsgs:
        found = False
        for rule in nsg.security_rules:
            if not (rule.access == SecurityAccess.ALLOW and rule.direction == SecurityDirection.INBOUND):
                continue
            if not _is_internet(rule.source_address_prefix):
                continue
            if rule.protocol == SecurityProtocol.ASTERISK:
                results.append(CheckResult(
                    control_id="N/A", status="fail", severity="Critical",
                    nsg_name=nsg.name, rule_name=rule.name,
                    evidence=f"NSG '{nsg.name}' has inbound rule '{rule.name}' allowing all protocols from the internet."
                ))
                found = True
            elif rule.destination_port_range == "*":
                results.append(CheckResult(
                    control_id="N/A", status="fail", severity="Critical",
                    nsg_name=nsg.name, rule_name=rule.name,
                    evidence=f"NSG '{nsg.name}' has inbound rule '{rule.name}' allowing all destination ports from the internet."
                ))
                found = True
            elif _ports_intersect(rule.destination_port_range, {80, 443}):
                continue
            else:
                severity = _compute_severity(1, True, _port_sensitivity(rule.destination_port_range, rule.protocol))
                results.append(CheckResult(
                    control_id="N/A", status="fail", severity=severity,
                    nsg_name=nsg.name, rule_name=rule.name,
                    evidence=f"NSG '{nsg.name}' has inbound rule '{rule.name}' exposing non-web ports {rule.destination_port_range} to the internet."
                ))
                found = True
        if not found:
            results.append(CheckResult(
                control_id="N/A", status="pass", severity="Low",
                nsg_name=nsg.name,
                evidence=f"NSG '{nsg.name}' has no overly broad inbound rules from the internet."
            ))
    return results

def check_missing_asgs(nsgs: list[NetworkSecurityGroup]) -> list[CheckResult]:
    results: list[CheckResult] = []
    for nsg in nsgs:
        found = False
        for rule in nsg.security_rules:
            if rule.access == SecurityAccess.ALLOW and rule.direction == SecurityDirection.INBOUND:
                if _is_internet(rule.source_address_prefix):
                    continue
                if _is_specific_ip(rule.source_address_prefix):
                    results.append(CheckResult(
                        control_id="N/A", status="fail", severity="Low",
                        nsg_name=nsg.name, rule_name=rule.name,
                        evidence=f"NSG '{nsg.name}' has inbound rule '{rule.name}' allowing traffic from a specific IP address {rule.source_address_prefix}. Consider using an Application Security Group (ASG) instead."
                    ))
                    found = True
                else:
                    continue
        if not found:
            results.append(CheckResult(
                control_id="N/A", status="pass", severity="Low",
                nsg_name=nsg.name,
                evidence=f"NSG '{nsg.name}' has no inbound rules allowing traffic from specific IP addresses. Consider using an Application Security Group (ASG) for better management."
            ))
    return results

def check_databricks_subnet_nsg(nsgs: list[NetworkSecurityGroup]) -> list[CheckResult]:
    results: list[CheckResult] = []
    found_databricks = False
    for nsg in nsgs:
        if any("databricks" in subnet.name.lower() for subnet in nsg.subnets):
            results.append(CheckResult(
                control_id="2.1.2", status="pass", severity="Medium",
                nsg_name=nsg.name,
                evidence=f"NSG '{nsg.name}' is associated with a Databricks subnet and has an NSG assigned."
            ))
            found_databricks = True
    if not found_databricks:
        results.append(CheckResult(
            control_id="2.1.2", status="manual", severity="Medium",
            nsg_name="N/A",
            evidence="No Databricks subnets found in any NSG. Manual verification of Databricks subnet NSG assignments is required."
        ))
    return results

def check_nsg_flow_logs_to_log_analytics(nsgs: list[NetworkSecurityGroup]) -> list[CheckResult]:
    return [CheckResult(
        control_id="6.1.1.5", status="manual", severity="Medium",
        nsg_name="N/A",
        evidence="Cannot be automated from NSG data alone. Manual verification required: ensure NSG flow logs are captured and sent to Log Analytics."
    )]

def check_vnet_flow_logs_to_log_analytics(nsgs: list[NetworkSecurityGroup]) -> list[CheckResult]:
    return [CheckResult(
        control_id="6.1.1.6", status="manual", severity="Medium",
        nsg_name="N/A",
        evidence="Cannot be automated from NSG data alone. Manual verification required: ensure VNet flow logs are captured and sent to Log Analytics."
    )]

def check_alert_create_update_nsg(nsgs: list[NetworkSecurityGroup]) -> list[CheckResult]:
    return [CheckResult(
        control_id="6.1.2.3", status="manual", severity="Medium",
        nsg_name="N/A",
        evidence="Cannot be automated from NSG data alone. Manual verification required: ensure Activity Log Alert exists for Create or Update Network Security Group."
    )]

def check_alert_delete_nsg(nsgs: list[NetworkSecurityGroup]) -> list[CheckResult]:
    return [CheckResult(
        control_id="6.1.2.4", status="manual", severity="Medium",
        nsg_name="N/A",
        evidence="Cannot be automated from NSG data alone. Manual verification required: ensure Activity Log Alert exists for Delete Network Security Group."
    )]

def check_network_watcher_enabled(nsgs: list[NetworkSecurityGroup]) -> list[CheckResult]:
    return [CheckResult(
        control_id="7.6", status="manual", severity="Medium",
        nsg_name="N/A",
        evidence="Cannot be automated from NSG data alone. Manual verification required: ensure Network Watcher is enabled for all Azure regions in use."
    )]

def check_network_security_perimeter(nsgs: list[NetworkSecurityGroup]) -> list[CheckResult]:
    return [CheckResult(
        control_id="7.16", status="manual", severity="Medium",
        nsg_name="N/A",
        evidence="Cannot be automated from NSG data alone. Manual verification required: ensure Network Security Perimeter is used to secure PaaS resources."
    )]

def check_ddos_protection(nsgs: list[NetworkSecurityGroup]) -> list[CheckResult]:
    return [CheckResult(
        control_id="8.5", status="manual", severity="Medium",
        nsg_name="N/A",
        evidence="Cannot be automated from NSG data alone. Manual verification required: ensure DDoS Network Protection is enabled on virtual networks."
    )]

def _find_flow_log(flow_logs: list[FlowLog], nsg_name: str) -> FlowLog | None:
    for fl in flow_logs:
        if fl.target_resource_id.endswith(f"/{nsg_name}"):
            return fl
    return None


def check_nsg_flow_log_retention(nsgs: list[NetworkSecurityGroup], flow_logs: list[FlowLog]) -> list[CheckResult]:
    results: list[CheckResult] = []
    for nsg in nsgs:
        fl = _find_flow_log(flow_logs, nsg.name)
        if fl is None:
            results.append(CheckResult(
                control_id="7.5", status="fail", severity="High",
                nsg_name=nsg.name,
                evidence=f"NSG '{nsg.name}' has no flow log configured."
            ))
        elif not fl.enabled:
            results.append(CheckResult(
                control_id="7.5", status="fail", severity="High",
                nsg_name=nsg.name,
                evidence=f"Flow log for NSG '{nsg.name}' exists but is not enabled."
            ))
        elif fl.retention_policy and fl.retention_policy.days < 90:
            results.append(CheckResult(
                control_id="7.5", status="fail", severity="High",
                nsg_name=nsg.name,
                evidence=f"Flow log for NSG '{nsg.name}' has retention of {fl.retention_policy.days} days, which is less than 90."
            ))
        else:
            results.append(CheckResult(
                control_id="7.5", status="pass", severity="High",
                nsg_name=nsg.name,
                evidence=f"Flow log for NSG '{nsg.name}' is enabled with retention >= 90 days."
            ))
    return results


def check_vnet_flow_log_retention(nsgs: list[NetworkSecurityGroup], flow_logs: list[FlowLog]) -> list[CheckResult]:
    results: list[CheckResult] = []
    vnet_logs = [fl for fl in flow_logs if "virtualNetworks" in fl.target_resource_id]
    if not vnet_logs:
        results.append(CheckResult(
            control_id="7.8", status="manual", severity="Medium",
            nsg_name="N/A",
            evidence="Cannot be automated from NSG data alone. Manual verification required: ensure VNet flow logs are enabled with retention >= 90 days."
        ))
        return results
    for fl in vnet_logs:
        if not fl.enabled:
            results.append(CheckResult(
                control_id="7.8", status="fail", severity="High",
                nsg_name=fl.name,
                evidence=f"VNet flow log '{fl.name}' is not enabled."
            ))
        elif fl.retention_policy and fl.retention_policy.days < 90:
            results.append(CheckResult(
                control_id="7.8", status="fail", severity="High",
                nsg_name=fl.name,
                evidence=f"VNet flow log '{fl.name}' has retention of {fl.retention_policy.days} days, which is less than 90."
            ))
        else:
            results.append(CheckResult(
                control_id="7.8", status="pass", severity="High",
                nsg_name=fl.name,
                evidence=f"VNet flow log '{fl.name}' is enabled with retention >= 90 days."
            ))
    return results


def run_engine(nsgs: list[NetworkSecurityGroup], flow_logs: list[FlowLog] | None = None) -> list[CheckResult]:
    results = []
    results.extend(check_rdp_internet(nsgs))
    results.extend(check_ssh_internet(nsgs))
    results.extend(check_udp_internet(nsgs))
    results.extend(check_https_internet(nsgs))
    results.extend(check_any_any_rule(nsgs))
    results.extend(check_missing_deny_all(nsgs))
    results.extend(check_subnet_association(nsgs))
    results.extend(check_overly_broad_service_tags(nsgs))
    results.extend(check_missing_asgs(nsgs))
    results.extend(check_databricks_subnet_nsg(nsgs))
    results.extend(check_nsg_flow_logs_to_log_analytics(nsgs))
    results.extend(check_vnet_flow_logs_to_log_analytics(nsgs))
    results.extend(check_alert_create_update_nsg(nsgs))
    results.extend(check_alert_delete_nsg(nsgs))
    results.extend(check_network_watcher_enabled(nsgs))
    results.extend(check_network_security_perimeter(nsgs))
    results.extend(check_ddos_protection(nsgs))
    if flow_logs is not None:
        results.extend(check_nsg_flow_log_retention(nsgs, flow_logs))
        results.extend(check_vnet_flow_log_retention(nsgs, flow_logs))
    return results