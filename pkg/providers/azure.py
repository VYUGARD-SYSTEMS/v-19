"""
Azure Cloud Scanner for v-19

Scans Azure environments for identity risks:
- Managed Identities with overpermission (Owner role)
- Service Principals with dangerous permissions
- RBAC assignments (especially at subscription level)
- Federated credentials
"""

import logging
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AzureIdentity:
    """Represents an Azure identity (service principal, managed identity)"""
    name: str
    type: str  # "service_principal", "managed_identity", "user"
    id: str
    principal_id: Optional[str]
    permissions: List[str]
    role_assignments: List[str]
    federated_credentials: List[str]
    subscription_id: str
    created_date: Optional[str] = None


class AzureScanner:
    """Real Azure RBAC and identity scanner using azure-identity"""
    
    def __init__(self, credentials: Dict, subscription_id: Optional[str] = None):
        self.credentials = credentials
        self.subscription_id = subscription_id or credentials.get("subscription_id")
        
        # Default to first available subscription if not provided
        if not self.subscription_id:
            # Will be set during initialization when we can query subscriptions
            self.subscription_id = None
        
        self.graph_client = None
        self.mgmt_client = None
        self.scan_start = None
        self.identities = []
        
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Initialize Azure SDK clients with resolved credentials"""
        try:
            from azure.identity import ClientSecretCredential, ManagedIdentityCredential, DefaultAzureCredential
            from azure.mgmt.authorization import AuthorizationManagementClient
            from azure.mgmt.subscription import SubscriptionClient
            
            # Determine which credential type to use based on what we resolved
            if self.credentials.get("client_secret"):
                # Service principal
                credential = ClientSecretCredential(
                    tenant_id=self.credentials.get("tenant_id"),
                    client_id=self.credentials.get("client_id"),
                    client_secret=self.credentials.get("client_secret")
                )
            elif self.credentials.get("source") == "Azure Managed Identity (IMDS)":
                # Managed identity
                credential = ManagedIdentityCredential(
                    client_id=self.credentials.get("client_id")
                )
            else:
                # Try default credentials
                credential = DefaultAzureCredential()
            
            # If subscription not provided, get the first available one
            if not self.subscription_id:
                try:
                    sub_client = SubscriptionClient(credential)
                    subscriptions = list(sub_client.subscriptions.list())
                    if subscriptions:
                        self.subscription_id = subscriptions[0].subscription_id
                        logger.info(f"✓ Azure: Using subscription {self.subscription_id} (first available)")
                    else:
                        logger.error("✗ Azure: No subscriptions found")
                        return False
                except Exception as e:
                    logger.error(f"✗ Azure: Failed to get subscriptions: {e}")
                    return False
            
            # Create authorization client with subscription_id as named parameter
            self.mgmt_client = AuthorizationManagementClient(
                credential=credential,
                subscription_id=self.subscription_id
            )
            
            logger.info(f"✓ Azure: Connected to subscription {self.subscription_id}")
            return True
        
        except ImportError:
            logger.error("azure-identity not installed. Install with: pip install azure-identity azure-mgmt-authorization azure-mgmt-subscription")
            return False
        except Exception as e:
            logger.error(f"✗ Azure: Failed to initialize clients: {e}")
            return False
    
    def scan(self) -> Tuple[List[AzureIdentity], float]:
        """
        Scan Azure for identity-related risks
        
        Returns:
            Tuple of (identities_list, scan_duration_ms)
        """
        if not self.mgmt_client or not self.subscription_id:
            return [], 0
        
        self.scan_start = time.time()
        
        try:
            # Scan RBAC assignments
            self._scan_rbac_assignments()
            
            scan_duration_ms = (time.time() - self.scan_start) * 1000
            logger.info(f"✓ Azure: Scanned {len(self.identities)} identities in {scan_duration_ms:.1f}ms")
            
            return self.identities, scan_duration_ms
        
        except Exception as e:
            logger.error(f"✗ Azure: Scan failed: {e}")
            return [], 0
    
    def _scan_rbac_assignments(self):
        """Scan RBAC assignments at subscription level"""
        if not self.subscription_id or not self.mgmt_client:
            logger.warning("Subscription ID or client not available for RBAC scan")
            return
        
        try:
            scope = f"/subscriptions/{self.subscription_id}"
            
            # List all role assignments at subscription scope
            assignments = self.mgmt_client.role_assignments.list_by_scope(scope=scope)
            
            for assignment in assignments:
                identity_name = assignment.principal_id  # Would need Graph API to get friendly name
                
                # Get role definition
                role_id = assignment.role_definition_id
                role_name = self._get_role_name(role_id)
                
                # Check for dangerous roles
                is_dangerous = self._is_dangerous_role(role_name)
                
                identity = AzureIdentity(
                    name=identity_name,
                    type="rbac_assignment",
                    id=assignment.id,
                    principal_id=assignment.principal_id,
                    permissions=[role_name],
                    role_assignments=[role_name],
                    federated_credentials=[],
                    subscription_id=self.subscription_id,
                    created_date=str(assignment.created_on) if hasattr(assignment, 'created_on') else None
                )
                
                if is_dangerous:
                    self.identities.append(identity)
        
        except Exception as e:
            logger.warning(f"Failed to scan RBAC assignments: {e}")
    
    def _get_role_name(self, role_id: str) -> str:
        """Get friendly role name from role definition ID"""
        # Common role IDs → names mapping
        role_mapping = {
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
            "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
            "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
        }
        
        return role_mapping.get(role_id, role_id[-8:])  # Return last 8 chars if unknown
    
    def _is_dangerous_role(self, role_name: str) -> bool:
        """Check if role is dangerous (Owner, Contributor at subscription scope)"""
        dangerous_roles = ["Owner", "Contributor", "User Access Administrator"]
        return any(dangerous in role_name for dangerous in dangerous_roles)
    
    def detect_risks(self) -> List[Dict]:
        """
        Detect risks in scanned identities
        
        Returns:
            List of risk findings
        """
        risks = []
        
        for identity in self.identities:
            # Dangerous role assignments
            for role in identity.role_assignments:
                if "Owner" in role:
                    risks.append({
                        "type": "dangerous_rbac",
                        "severity": "CRITICAL",
                        "identity": identity.name,
                        "role": role,
                        "description": f"Principal {identity.principal_id} has Owner role on subscription"
                    })
                elif "Contributor" in role:
                    risks.append({
                        "type": "dangerous_rbac",
                        "severity": "HIGH",
                        "identity": identity.name,
                        "role": role,
                        "description": f"Principal {identity.principal_id} has Contributor role on subscription"
                    })
            
            # Federated credentials
            for fed_cred in identity.federated_credentials:
                risks.append({
                    "type": "federated_credential",
                    "severity": "MEDIUM",
                    "identity": identity.name,
                    "credential": fed_cred,
                    "description": f"Principal {identity.principal_id} has federated credential"
                })
        
        return risks


if __name__ == "__main__":
    # Test Azure scanner
    from internal.auth.credentials import CredentialChain
    
    logging.basicConfig(level=logging.INFO)
    
    print("\n=== Azure Scanner Test ===\n")
    
    chain = CredentialChain(verbose=True)
    azure_creds = chain.resolve_azure_credentials()
    
    if azure_creds:
        scanner = AzureScanner(azure_creds)
        identities, duration = scanner.scan()
        
        print(f"\nScanned {len(identities)} identities in {duration:.1f}ms\n")
        
        risks = scanner.detect_risks()
        if risks:
            print(f"Detected {len(risks)} risks:")
            for risk in risks[:10]:
                print(f"  - [{risk['severity']}] {risk['type']}: {risk['description']}")
    else:
        print("No Azure credentials found")
