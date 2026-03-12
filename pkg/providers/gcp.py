"""
GCP Cloud Scanner for v-19

Scans Google Cloud environments for identity risks:
- Service accounts with dangerous permissions
- Workload Identity Federation
- Cross-project access
"""

import logging
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class GCPIdentity:
    """Represents a GCP identity (service account)"""
    name: str
    type: str  # "service_account"
    email: str
    project_id: str
    permissions: List[str]
    roles: List[str]
    workload_id_pools: List[str]
    display_name: Optional[str] = None
    disabled: bool = False


class GCPScanner:
    """Real GCP IAM scanner using google-cloud-iam"""
    
    def __init__(self, credentials: Dict, project_id: Optional[str] = None):
        self.credentials = credentials
        self.project_id = project_id or credentials.get("project_id")
        self.iam_client = None
        self.scan_start = None
        self.identities = []
        
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Initialize GCP clients with resolved credentials"""
        try:
            from google.cloud import iam_admin_v1
            from google.auth import default
            import json
            import os
            
            # Create credentials from resolved credentials
            if self.credentials.get("type") == "service_account" and self.credentials.get("path"):
                try:
                    # Credentials is a service account JSON file path
                    cred_path = self.credentials.get("path")
                    if cred_path:
                        with open(cred_path) as f:
                            sa_json = json.load(f)
                        from google.oauth2.service_account import Credentials
                        creds = Credentials.from_service_account_info(sa_json)
                    else:
                        creds, _ = default()
                except (FileNotFoundError, IOError):
                    # Fall back to Application Default Credentials if file not found
                    creds, _ = default()
            else:
                # Try Application Default Credentials (environment variable, ADC, etc)
                creds, _ = default()
            
            self.iam_client = iam_admin_v1.IAMClient(credentials=creds)
            
            logger.info(f"✓ GCP: Connected to project {self.project_id}")
            return True
        
        except ImportError as e:
            logger.error(f"google-cloud-iam not installed. Install with: pip install google-cloud-iam. Error: {e}")
            return False
        except Exception as e:
            logger.error(f"✗ GCP: Failed to initialize clients: {e}")
            return False
    
    def scan(self) -> Tuple[List[GCPIdentity], float]:
        """
        Scan GCP for identity-related risks
        
        Returns:
            Tuple of (identities_list, scan_duration_ms)
        """
        if not self.iam_client or not self.project_id:
            return [], 0
        
        self.scan_start = time.time()
        
        try:
            # Scan service accounts
            self._scan_service_accounts()
            
            scan_duration_ms = (time.time() - self.scan_start) * 1000
            logger.info(f"✓ GCP: Scanned {len(self.identities)} identities in {scan_duration_ms:.1f}ms")
            
            return self.identities, scan_duration_ms
        
        except Exception as e:
            logger.error(f"✗ GCP: Scan failed: {e}")
            return [], 0
    
    def _scan_service_accounts(self):
        """Scan for service accounts and their permissions"""
        if not self.iam_client or not self.project_id:
            return
        try:
            from google.cloud.iam_admin_v1 import ListServiceAccountsRequest
            
            request = ListServiceAccountsRequest(
                name=f"projects/{self.project_id}"
            )
            
            if self.iam_client:
                service_accounts = self.iam_client.list_service_accounts(request=request)
                
                for sa in service_accounts.accounts:
                    # Get roles for this service account
                    roles = self._get_sa_roles(sa.email)
                    
                    # Extract permissions from roles (simplified - would need role definitions)
                    permissions = [role.replace("roles/", "") for role in roles]
                    
                    identity = GCPIdentity(
                        name=sa.email.split("@")[0],
                        type="service_account",
                        email=sa.email,
                        project_id=self.project_id,
                        permissions=permissions,
                        roles=roles,
                        workload_id_pools=[],
                        display_name=sa.display_name,
                        disabled=sa.disabled
                    )
                    
                    self.identities.append(identity)
        
        except Exception as e:
            logger.warning(f"Failed to scan service accounts: {e}")
    
    def _get_sa_roles(self, service_account_email: str) -> List[str]:
        """Get roles assigned to a service account via project IAM policy"""
        if not self.iam_client:
            return []
        try:
            from google.cloud.iam_admin_v1 import GetIamPolicyRequest
            
            resource = f"projects/{self.project_id}"
            
            # Get IAM policy for the project
            policy_request = GetIamPolicyRequest(resource=resource)
            policy = self.iam_client.get_iam_policy(request=policy_request)
            
            roles = []
            
            # Parse bindings to find roles for this service account
            for binding in policy.bindings:
                members = binding.members or []
                
                # Check if service account is in members
                sa_member = f"serviceAccount:{service_account_email}"
                if sa_member in members:
                    # Extract role name (format is roles/xyz)
                    role_name = binding.role
                    roles.append(role_name)
            
            return roles
        except Exception as e:
            logger.debug(f"Failed to get roles for {service_account_email}: {e}")
            return []
    
    def detect_risks(self) -> List[Dict]:
        """
        Detect risks in GCP identities
        
        Returns:
            List of risk findings
        """
        risks = []
        
        for identity in self.identities:
            # Check for dangerous roles
            for role in identity.roles:
                if "admin" in role.lower() or "editor" in role.lower():
                    risks.append({
                        "type": "dangerous_role",
                        "severity": "HIGH",
                        "identity": identity.email,
                        "role": role,
                        "description": f"Service account {identity.email} has dangerous role: {role}"
                    })
            
            # Check for workload identity
            if identity.workload_id_pools:
                risks.append({
                    "type": "workload_identity",
                    "severity": "MEDIUM",
                    "identity": identity.email,
                    "pools": identity.workload_id_pools,
                    "description": f"Service account {identity.email} has workload identity federation"
                })
        
        return risks


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("\n=== GCP Scanner Test ===\n")
    print("GCP scanner requires GOOGLE_APPLICATION_CREDENTIALS env var")
