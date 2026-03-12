"""
Kubernetes Scanner for v-19

Scans Kubernetes clusters for identity risks:
- Service accounts with dangerous roles
- RBAC overpermission
- Pod security policy violations
"""

import logging
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class K8sIdentity:
    """Represents a Kubernetes service account"""
    name: str
    namespace: str
    type: str  # "service_account"
    role_bindings: List[str]
    permissions: List[str]
    secrets: List[str]
    automount_service_account_token: bool = True


class KubernetesScanner:
    """Real Kubernetes RBAC scanner using kubernetes client"""
    
    def __init__(self, credentials: Dict, context: Optional[str] = None):
        self.credentials = credentials
        self.context = context or credentials.get("context")
        self.v1_client = None
        self.rbac_client = None
        self.scan_start = None
        self.identities = []
        
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Initialize Kubernetes clients"""
        try:
            from kubernetes import client, config, stream
            from kubernetes.config.incluster_config import load_incluster_config
            
            try:
                # Try in-cluster config first
                load_incluster_config()
                logger.info("✓ Kubernetes: Using in-cluster service account")
            except:
                # Try kubeconfig file
                kubeconfig = self.credentials.get("kubeconfig")
                context = self.credentials.get("context")
                
                if context:
                    config.load_kube_config(config_file=kubeconfig, context=context)
                else:
                    config.load_kube_config(config_file=kubeconfig)
                logger.info(f"✓ Kubernetes: Using kubeconfig ({kubeconfig}) context: {context}")
            
            self.v1_client = client.CoreV1Api()
            self.rbac_client = client.RbacAuthorizationV1Api()
            
            return True
        
        except ImportError:
            logger.error("kubernetes not installed. Install with: pip install kubernetes")
            return False
        except Exception as e:
            logger.error(f"✗ Kubernetes: Failed to initialize: {e}")
            return False
    
    def scan(self) -> Tuple[List[K8sIdentity], float]:
        """
        Scan Kubernetes cluster for identity risks
        
        Returns:
            Tuple of (identities_list, scan_duration_ms)
        """
        if not self.v1_client:
            return [], 0
        
        self.scan_start = time.time()
        
        try:
            # Scan service accounts
            self._scan_service_accounts()
            
            # Scan role bindings
            self._scan_role_bindings()
            
            scan_duration_ms = (time.time() - self.scan_start) * 1000
            logger.info(f"✓ Kubernetes: Scanned {len(self.identities)} service accounts in {scan_duration_ms:.1f}ms")
            
            return self.identities, scan_duration_ms
        
        except Exception as e:
            logger.error(f"✗ Kubernetes: Scan failed: {e}")
            return [], 0
    
    def _scan_service_accounts(self):
        """Scan all service accounts in the cluster"""
        if not self.v1_client:
            return
        try:
            # Get service accounts from all namespaces
            sa_list = self.v1_client.list_service_account_for_all_namespaces()
            
            for sa in sa_list.items:
                automount = sa.automount_service_account_token if hasattr(sa, 'automount_service_account_token') else True
                
                identity = K8sIdentity(
                    name=sa.metadata.name,
                    namespace=sa.metadata.namespace,
                    type="service_account",
                    role_bindings=[],
                    permissions=[],
                    secrets=self._get_secrets_for_sa(sa.metadata.name, sa.metadata.namespace),
                    automount_service_account_token=automount
                )
                
                self.identities.append(identity)
        
        except Exception as e:
            logger.warning(f"Failed to scan service accounts: {e}")
    
    def _get_secrets_for_sa(self, sa_name: str, namespace: str) -> List[str]:
        """Get secrets for a service account"""
        if not self.v1_client:
            return []
        try:
            secrets = self.v1_client.list_namespaced_secret(namespace)
            sa_secrets = []
            
            for secret in secrets.items:
                # Check if secret is for this SA
                if secret.metadata.annotations:
                    if secret.metadata.annotations.get("kubernetes.io/service-account.name") == sa_name:
                        sa_secrets.append(secret.metadata.name)
            
            return sa_secrets
        except:
            return []
    
    def _scan_role_bindings(self):
        """Scan role bindings for risky assignments"""
        if not self.rbac_client or not self.v1_client:
            return
        try:
            # Get cluster role bindings (applies to all namespaces)
            crb_list = self.rbac_client.list_cluster_role_binding()
            
            for crb in crb_list.items:
                for subject in crb.subjects or []:
                    if subject.kind == "ServiceAccount":
                        # Find matching service account
                        sa_ns = subject.namespace or "default"
                        sa_name = subject.name
                        
                        # Update the service account with this binding
                        for identity in self.identities:
                            if identity.name == sa_name and identity.namespace == sa_ns:
                                identity.role_bindings.append(crb.role_ref.name)
            
            # Get namespaced role bindings - iterate through each namespace
            if not self.v1_client:
                return
            ns_list = self.v1_client.list_namespace()
            for namespace_obj in ns_list.items:
                namespace = namespace_obj.metadata.name
                
                try:
                    rb_list = self.rbac_client.list_namespaced_role_binding(namespace=namespace)
                    
                    for rb in rb_list.items or []:
                        for subject in rb.subjects or []:
                            if subject.kind == "ServiceAccount":
                                sa_ns = subject.namespace or rb.metadata.namespace
                                sa_name = subject.name
                                
                                for identity in self.identities:
                                    if identity.name == sa_name and identity.namespace == sa_ns:
                                        identity.role_bindings.append(rb.role_ref.name)
                except Exception as ns_error:
                    logger.debug(f"Error scanning role bindings in {namespace}: {ns_error}")
        
        except Exception as e:
            logger.warning(f"Failed to scan role bindings: {e}")
    
    def detect_risks(self) -> List[Dict]:
        """
        Detect risks in Kubernetes identities
        
        Returns:
            List of risk findings
        """
        risks = []
        
        for identity in self.identities:
            # Check for dangerous role bindings
            for binding in identity.role_bindings:
                if binding in ["cluster-admin", "admin", "edit"]:
                    risks.append({
                        "type": "dangerous_rbac",
                        "severity": "CRITICAL" if binding == "cluster-admin" else "HIGH",
                        "identity": f"{identity.namespace}/{identity.name}",
                        "role": binding,
                        "description": f"Service account {identity.name} has dangerous role: {binding}"
                    })
            
            # Check for automounted tokens
            if identity.automount_service_account_token and identity.role_bindings:
                risks.append({
                    "type": "automounted_token",
                    "severity": "MEDIUM",
                    "identity": f"{identity.namespace}/{identity.name}",
                    "role_bindings": identity.role_bindings,
                    "description": f"Service account {identity.name} automounts token with roles: {', '.join(identity.role_bindings)}"
                })
        
        return risks


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("\n=== Kubernetes Scanner Test ===\n")
    print("Kubernetes scanner requires kubeconfig at ~/.kube/config or KUBECONFIG env var")
