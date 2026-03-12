"""
AWS Cloud Scanner for v-19

Scans AWS environments for identity risks:
- IAM roles with overpermission (admin, * actions)
- Cross-account access chains
- STS sessions
- Role federation (OIDC, SAML)
"""

import logging
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AWSIdentity:
    """Represents an AWS identity (role, user, or service account)"""
    name: str
    type: str  # "role", "user", "assume_role_policy"
    arn: str
    permissions: List[str]
    trust_relationships: List[str]
    federation_provider: Optional[str] = None
    external_account_id: Optional[str] = None
    region: str = "us-east-1"
    created_date: Optional[str] = None
    last_used: Optional[str] = None


class AWSScanner:
    """Real AWS IAM and STS scanner using boto3"""
    
    def __init__(self, credentials: Dict, region: str = "us-east-1"):
        self.credentials = credentials
        self.region = region
        self.iam_client = None
        self.sts_client = None
        self.scan_start = None
        self.identities = []
        
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Initialize boto3 clients with resolved credentials"""
        try:
            import boto3
            from botocore.exceptions import NoCredentialsError
            
            # Create session with resolved credentials
            if self.credentials.get("source") == "environment":
                # Use environment variables directly
                session = boto3.Session(
                    region_name=self.region
                )
            else:
                # Use explicit credentials (for programmatic access)
                session = boto3.Session(
                    aws_access_key_id=self.credentials.get("access_key_id"),
                    aws_secret_access_key=self.credentials.get("secret_access_key"),
                    aws_session_token=self.credentials.get("session_token"),
                    region_name=self.credentials.get("region", self.region)
                )
            
            self.iam_client = session.client("iam")
            self.sts_client = session.client("sts")
            
            # Verify credentials work
            identity = self.sts_client.get_caller_identity()
            self.account_id = identity["Account"]
            
            logger.info(f"✓ AWS: Connected as {identity['Arn']}")
            return True
        
        except ImportError:
            logger.error("boto3 not installed. Install with: pip install boto3")
            return False
        except Exception as e:
            logger.error(f"✗ AWS: Failed to initialize clients: {e}")
            return False
    
    def scan(self) -> Tuple[List[AWSIdentity], float]:
        """
        Scan AWS for identity-related risks
        
        Returns:
            Tuple of (identities_list, scan_duration_ms)
        """
        if not self.iam_client:
            return [], 0
        
        self.scan_start = time.time()
        
        try:
            # Scan IAM roles
            self._scan_roles()
            
            # Scan IAM users
            self._scan_users()
            
            # Scan STS sessions
            self._scan_sts_sessions()
            
            scan_duration_ms = (time.time() - self.scan_start) * 1000
            logger.info(f"✓ AWS: Scanned {len(self.identities)} identities in {scan_duration_ms:.1f}ms")
            
            return self.identities, scan_duration_ms
        
        except Exception as e:
            logger.error(f"✗ AWS: Scan failed: {e}")
            return [], 0
    
    def _scan_roles(self):
        """Scan IAM roles for risks"""
        if not self.iam_client:
            return
        try:
            paginator = self.iam_client.get_paginator("list_roles")
            
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role["RoleName"]
                    
                    # Get attached policies
                    attached_policies = self._get_role_permissions(role_name)
                    
                    # Parse trust relationship
                    trust_rel = role.get("AssumeRolePolicyDocument", {})
                    trust_chains = self._parse_trust_relationship(trust_rel)
                    
                    # Extract federation info
                    federation_provider = None
                    external_account = None
                    
                    if trust_chains:
                        # Check for federated access
                        statements = trust_rel.get("Statement", [])
                        for stmt in statements:
                            principal = stmt.get("Principal", {})
                            if isinstance(principal, dict):
                                if "Federated" in principal:
                                    federation_provider = principal["Federated"]
                                if "AWS" in principal:
                                    aws_principal = principal["AWS"]
                                    if isinstance(aws_principal, str) and ":root" in aws_principal:
                                        external_account = aws_principal.split(":")[4]
                    
                    identity = AWSIdentity(
                        name=role_name,
                        type="role",
                        arn=role["Arn"],
                        permissions=attached_policies,
                        trust_relationships=trust_chains,
                        federation_provider=federation_provider,
                        external_account_id=external_account,
                        region=self.region,
                        created_date=role["CreateDate"].isoformat() if "CreateDate" in role else None
                    )
                    
                    self.identities.append(identity)
        
        except Exception as e:
            logger.warning(f"Failed to scan IAM roles: {e}")
    
    def _scan_users(self):
        """Scan IAM users"""
        if not self.iam_client:
            return
        try:
            paginator = self.iam_client.get_paginator("list_users")
            
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    
                    # Get attached policies
                    user_policies = self._get_user_permissions(user_name)
                    
                    identity = AWSIdentity(
                        name=user_name,
                        type="user",
                        arn=user["Arn"],
                        permissions=user_policies,
                        trust_relationships=[],
                        region=self.region,
                        created_date=user["CreateDate"].isoformat() if "CreateDate" in user else None
                    )
                    
                    self.identities.append(identity)
        
        except Exception as e:
            logger.warning(f"Failed to scan IAM users: {e}")
    
    def _scan_sts_sessions(self):
        """Scan STS sessions and active credentials"""
        if not self.sts_client:
            return
        try:
            # Get caller identity for current session
            identity = self.sts_client.get_caller_identity()
            
            # This shows we have valid credentials (simplified for STS)
            logger.debug(f"Current STS identity: {identity['Arn']}")
        
        except Exception as e:
            logger.warning(f"Failed to scan STS sessions: {e}")
    
    def _get_role_permissions(self, role_name: str) -> List[str]:
        """Get all permissions attached to an IAM role"""
        permissions = []
        
        if not self.iam_client:
            return permissions
        
        try:
            # Attached managed policies
            paginator = self.iam_client.get_paginator("list_attached_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                for policy in page.get("AttachedPolicies", []):
                    permissions.append(f"managed:{policy['PolicyName']}")
            
            # Inline policies
            paginator = self.iam_client.get_paginator("list_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                for policy_name in page.get("PolicyNames", []):
                    try:
                        policy_doc = self.iam_client.get_role_policy(
                            RoleName=role_name,
                            PolicyName=policy_name
                        )
                        
                        # Extract actions from policy
                        policy = policy_doc.get("RolePolicyDocument", {})
                        statements = policy.get("Statement", [])
                        
                        for stmt in statements:
                            if stmt.get("Effect") == "Allow":
                                actions = stmt.get("Action", [])
                                if isinstance(actions, str):
                                    permissions.append(actions)
                                else:
                                    permissions.extend(actions)
                    except:
                        permissions.append(f"inline:{policy_name}")
        
        except Exception as e:
            logger.debug(f"Failed to get permissions for role {role_name}: {e}")
        
        return list(set(permissions))  # Remove duplicates
    
    def _get_user_permissions(self, user_name: str) -> List[str]:
        """Get all permissions attached to an IAM user"""
        permissions = []
        
        if not self.iam_client:
            return permissions
        
        try:
            # Attached managed policies
            paginator = self.iam_client.get_paginator("list_attached_user_policies")
            for page in paginator.paginate(UserName=user_name):
                for policy in page.get("AttachedPolicies", []):
                    permissions.append(f"managed:{policy['PolicyName']}")
            
            # Inline policies
            paginator = self.iam_client.get_paginator("list_user_policies")
            for page in paginator.paginate(UserName=user_name):
                for policy_name in page.get("PolicyNames", []):
                    permissions.append(f"inline:{policy_name}")
        
        except Exception as e:
            logger.debug(f"Failed to get permissions for user {user_name}: {e}")
        
        return permissions
    
    def _parse_trust_relationship(self, trust_policy: Dict) -> List[str]:
        """Parse IAM trust relationship policy"""
        trust_chains = []
        
        try:
            statements = trust_policy.get("Statement", [])
            
            for stmt in statements:
                principal = stmt.get("Principal", {})
                
                if isinstance(principal, str) and principal == "*":
                    trust_chains.append("Public (any AWS principal)")
                elif isinstance(principal, dict):
                    if "AWS" in principal:
                        aws_principals = principal["AWS"]
                        if isinstance(aws_principals, str):
                            trust_chains.append(aws_principals)
                        else:
                            trust_chains.extend(aws_principals)
                    
                    if "Service" in principal:
                        service = principal["Service"]
                        if isinstance(service, str):
                            trust_chains.append(f"service:{service}")
                        else:
                            trust_chains.extend([f"service:{s}" for s in service])
                    
                    if "Federated" in principal:
                        trust_chains.append(f"federated:{principal['Federated']}")
        
        except Exception as e:
            logger.debug(f"Failed to parse trust relationship: {e}")
        
        return trust_chains
    
    def detect_risks(self) -> List[Dict]:
        """
        Detect risks in scanned identities
        
        Returns:
            List of risk findings
        """
        risks = []
        
        for identity in self.identities:
            # Check for admin or overpermission
            for perm in identity.permissions:
                if "admin" in perm.lower() or perm == "*" or "iam:*" in perm.lower():
                    risks.append({
                        "type": "overpermission",
                        "severity": "CRITICAL" if "*" in perm else "HIGH",
                        "identity": identity.name,
                        "permission": perm,
                        "description": f"Identity {identity.name} has overpermissive policy: {perm}"
                    })
            
            # Check for cross-account access
            if identity.external_account_id:
                risks.append({
                    "type": "cross_account_access",
                    "severity": "HIGH",
                    "identity": identity.name,
                    "external_account": identity.external_account_id,
                    "description": f"Identity {identity.name} can assume role in account {identity.external_account_id}"
                })
            
            # Check for federation
            if identity.federation_provider:
                risks.append({
                    "type": "federation",
                    "severity": "MEDIUM",
                    "identity": identity.name,
                    "provider": identity.federation_provider,
                    "description": f"Identity {identity.name} has federation with {identity.federation_provider}"
                })
        
        return risks


if __name__ == "__main__":
    # Test AWS scanner
    from credentials import CredentialChain
    
    logging.basicConfig(level=logging.INFO)
    
    print("\n=== AWS Scanner Test ===\n")
    
    chain = CredentialChain(verbose=True)
    aws_creds = chain.resolve_aws_credentials()
    
    if aws_creds:
        scanner = AWSScanner(aws_creds)
        identities, duration = scanner.scan()
        
        print(f"\nFound {len(identities)} identities in {duration:.1f}ms\n")
        
        if identities:
            print("Sample identities:")
            for identity in identities[:5]:
                print(f"  - {identity.name} ({identity.type})")
        
        risks = scanner.detect_risks()
        if risks:
            print(f"\nDetected {len(risks)} risks:")
            for risk in risks[:10]:
                print(f"  - [{risk['severity']}] {risk['type']}: {risk['description']}")
    else:
        print("No AWS credentials found")
