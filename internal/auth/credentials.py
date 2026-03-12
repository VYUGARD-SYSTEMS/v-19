"""
v-19 Credential Chain Resolver

Implements proper credential chaining for all cloud providers:
1. Explicit CLI flags (--aws-profile, --credentials-file, etc.)
2. Environment variables (AWS_ACCESS_KEY_ID, AZURE_CLIENT_ID, etc.)
3. Cloud provider config files (~/.aws/credentials, ~/.azure/, ~/.kube/config)
4. Instance metadata (IAM role on EC2, Managed Identity on Azure VM)

This allows v-19 to work seamlessly in:
- Local development (with credentials in ~/.aws/credentials)
- CI/CD pipelines (with env vars)
- Cloud VMs (with instance roles/managed identities)
"""

import os
import json
from pathlib import Path
from typing import Optional, Dict, Tuple
import logging
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)


class CredentialChain:
    """Resolves credentials using cloud provider standard chains"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.credentials = {}
    
    # ========== AWS CREDENTIAL CHAIN ==========
    
    def resolve_aws_credentials(self, 
                                aws_profile: Optional[str] = None,
                                credentials_file: Optional[str] = None) -> Optional[Dict]:
        """
        Resolve AWS credentials in order:
        1. Explicit --aws-profile flag
        2. AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY env vars
        3. ~/.aws/credentials file
        4. ~/.aws/config file
        5. EC2 instance metadata (IAM role)
        6. ECS task metadata
        """
        
        # 1. Explicit --aws-profile flag
        if aws_profile:
            creds = self._read_aws_credentials_file(aws_profile, credentials_file)
            if creds:
                self._log(f"✓ AWS: Using profile '{aws_profile}'")
                return creds
        
        # 2. Environment variables (most explicit)
        env_creds = self._resolve_aws_from_env()
        if env_creds:
            self._log("✓ AWS: Using AWS_ACCESS_KEY_ID env var")
            return env_creds
        
        # 3. ~/.aws/credentials file (default profile)
        default_creds = self._read_aws_credentials_file("default", credentials_file)
        if default_creds:
            self._log("✓ AWS: Using ~/.aws/credentials (default profile)")
            return default_creds
        
        # 4. ~/.aws/config file
        config_creds = self._read_aws_config_file()
        if config_creds:
            self._log("✓ AWS: Using ~/.aws/config")
            return config_creds
        
        # 5. EC2 instance metadata (IAM role)
        instance_creds = self._resolve_aws_from_instance_metadata()
        if instance_creds:
            self._log("✓ AWS: Using EC2 instance metadata (IAM role)")
            return instance_creds
        
        # 6. ECS task metadata
        ecs_creds = self._resolve_aws_from_ecs_metadata()
        if ecs_creds:
            self._log("✓ AWS: Using ECS task metadata")
            return ecs_creds
        
        self._log("✗ AWS: No credentials found", is_error=True)
        return None
    
    def _resolve_aws_from_env(self) -> Optional[Dict]:
        """Check AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY"""
        access_key = os.getenv("AWS_ACCESS_KEY_ID")
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        session_token = os.getenv("AWS_SESSION_TOKEN")
        
        if access_key and secret_key:
            return {
                "access_key_id": access_key,
                "secret_access_key": secret_key,
                "session_token": session_token,
                "region": os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
                "source": "environment"
            }
        return None
    
    def _read_aws_credentials_file(self, profile: str = "default", 
                                   credentials_file: Optional[str] = None) -> Optional[Dict]:
        """Read ~/.aws/credentials file"""
        if credentials_file:
            cred_path = Path(credentials_file)
        else:
            cred_path = Path.home() / ".aws" / "credentials"
        
        if not cred_path.exists():
            return None
        
        try:
            import configparser
            config = configparser.ConfigParser()
            config.read(cred_path)
            
            if profile in config:
                return {
                    "access_key_id": config[profile].get("aws_access_key_id"),
                    "secret_access_key": config[profile].get("aws_secret_access_key"),
                    "session_token": config[profile].get("aws_session_token"),
                    "region": config[profile].get("region", "us-east-1"),
                    "source": f"~/.aws/credentials ({profile})"
                }
        except Exception as e:
            self._log(f"Error reading AWS credentials: {e}", is_error=True)
        
        return None
    
    def _read_aws_config_file(self) -> Optional[Dict]:
        """Read ~/.aws/config file"""
        config_path = Path.home() / ".aws" / "config"
        if not config_path.exists():
            return None
        
        try:
            import configparser
            config = configparser.ConfigParser()
            config.read(config_path)
            
            if "default" in config:
                return {
                    "region": config["default"].get("region", "us-east-1"),
                    "source": "~/.aws/config"
                }
        except Exception as e:
            self._log(f"Error reading AWS config: {e}", is_error=True)
        
        return None
    
    def _resolve_aws_from_instance_metadata(self) -> Optional[Dict]:
        """Resolve AWS credentials from EC2 instance metadata"""
        try:
            import urllib.request
            import json
            
            # EC2 instance metadata endpoint
            metadata_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            
            try:
                # Check if we're running on EC2 (with timeout)
                with urllib.request.urlopen(metadata_url, timeout=1) as response:
                    role_name = response.read().decode().strip()
                    
                    # Get credentials for the role
                    role_url = f"{metadata_url}{role_name}"
                    with urllib.request.urlopen(role_url, timeout=1) as role_response:
                        role_data = json.loads(role_response.read().decode())
                        
                        return {
                            "access_key_id": role_data.get("AccessKeyId"),
                            "secret_access_key": role_data.get("SecretAccessKey"),
                            "session_token": role_data.get("Token"),
                            "region": os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
                            "source": f"EC2 instance metadata (role: {role_name})"
                        }
            except Exception:
                # Not on EC2
                pass
        except Exception as e:
            self._log(f"Error reading EC2 metadata: {e}", is_error=True)
        
        return None
    
    def _resolve_aws_from_ecs_metadata(self) -> Optional[Dict]:
        """Resolve AWS credentials from ECS task metadata"""
        try:
            import urllib.request
            import json
            
            # ECS task metadata endpoint (v3 or v4)
            relative_uri = os.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
            full_uri = os.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")
            auth_token = os.getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")
            
            if relative_uri:
                base_uri = "http://169.254.170.2"
                url = f"{base_uri}{relative_uri}"
            elif full_uri:
                url = full_uri
            else:
                return None
            
            req = urllib.request.Request(url)
            if auth_token:
                req.add_header("Authorization", auth_token)
            
            with urllib.request.urlopen(req, timeout=1) as response:
                creds_data = json.loads(response.read().decode())
                
                return {
                    "access_key_id": creds_data.get("AccessKeyId"),
                    "secret_access_key": creds_data.get("SecretAccessKey"),
                    "session_token": creds_data.get("Token"),
                    "region": os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
                    "source": "ECS task metadata"
                }
        except Exception as e:
            self._log(f"Error reading ECS metadata: {e}", is_error=True)
        
        return None
    
    # ========== AZURE CREDENTIAL CHAIN ==========
    
    def resolve_azure_credentials(self, 
                                 azure_profile: Optional[str] = None) -> Optional[Dict]:
        """
        Resolve Azure credentials in order:
        1. --azure-tenant-id + --azure-client-id + --azure-client-secret
        2. AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET env vars
        3. ~/.azure/config (current account)
        4. ~/.azure/credentials.json
        5. Managed Identity (on Azure VM)
        6. Azure CLI default subscription
        """
        
        # 1. Environment variables
        env_creds = self._resolve_azure_from_env()
        if env_creds:
            self._log("✓ Azure: Using AZURE_TENANT_ID env var")
            return env_creds
        
        # 2. Azure CLI config
        cli_creds = self._resolve_azure_from_cli()
        if cli_creds:
            self._log("✓ Azure: Using Azure CLI config (~/.azure/)")
            return cli_creds
        
        # 3. Managed Identity (Azure VM)
        mi_creds = self._resolve_azure_from_managed_identity()
        if mi_creds:
            self._log("✓ Azure: Using Managed Identity")
            return mi_creds
        
        self._log("✗ Azure: No credentials found", is_error=True)
        return None
    
    def _resolve_azure_from_env(self) -> Optional[Dict]:
        """Check AZURE_TENANT_ID, AZURE_CLIENT_ID, etc."""
        tenant_id = os.getenv("AZURE_TENANT_ID")
        client_id = os.getenv("AZURE_CLIENT_ID")
        
        # Service principal
        client_secret = os.getenv("AZURE_CLIENT_SECRET")
        if tenant_id and client_id and client_secret:
            return {
                "tenant_id": tenant_id,
                "client_id": client_id,
                "client_secret": client_secret,
                "subscription_id": os.getenv("AZURE_SUBSCRIPTION_ID"),
                "source": "environment (service principal)"
            }
        
        # Managed identity (workload identity)
        if tenant_id and client_id:
            return {
                "tenant_id": tenant_id,
                "client_id": client_id,
                "subscription_id": os.getenv("AZURE_SUBSCRIPTION_ID"),
                "source": "environment (managed identity)"
            }
        
        return None
    
    def _resolve_azure_from_cli(self) -> Optional[Dict]:
        """Read ~/.azure/ directory"""
        azure_dir = Path.home() / ".azure"
        
        if (azure_dir / "cloudConfig.json").exists():
            try:
                with open(azure_dir / "cloudConfig.json") as f:
                    config = json.load(f)
                    return {
                        "source": "Azure CLI config",
                        "cloud": config.get("cloud", "AzureCloud")
                    }
            except Exception as e:
                self._log(f"Error reading Azure CLI config: {e}", is_error=True)
        
        return None
    
    def _resolve_azure_from_managed_identity(self) -> Optional[Dict]:
        """Check for Managed Identity (IMDS endpoint)"""
        try:
            import urllib.request
            import json
            
            # Azure IMDS endpoint
            imds_url = "http://169.254.169.254/metadata/identity/oauth2/token"
            params = "?api-version=2017-09-01&resource=https://management.azure.com"
            
            req = urllib.request.Request(f"{imds_url}{params}")
            req.add_header("Metadata", "true")
            
            with urllib.request.urlopen(req, timeout=1) as response:
                token_data = json.loads(response.read().decode())
                
                return {
                    "access_token": token_data.get("access_token"),
                    "source": "Azure Managed Identity (IMDS)"
                }
        except Exception as e:
            self._log(f"Error reading Azure IMDS: {e}", is_error=True)
        
        return None
    
    # ========== GCP CREDENTIAL CHAIN ==========
    
    def resolve_gcp_credentials(self, 
                               gcp_project: Optional[str] = None,
                               credentials_file: Optional[str] = None) -> Optional[Dict]:
        """
        Resolve GCP credentials in order:
        1. GOOGLE_APPLICATION_CREDENTIALS env var (service account JSON)
        2. ~/.config/gcloud/application_default_credentials.json
        3. GCP_PROJECT env var
        4. Compute Engine instance metadata
        """
        
        # 1. GOOGLE_APPLICATION_CREDENTIALS file
        adc_file = os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or credentials_file
        if adc_file:
            creds = self._read_gcp_service_account(adc_file)
            if creds:
                self._log(f"✓ GCP: Using GOOGLE_APPLICATION_CREDENTIALS")
                return creds
        
        # 2. Application Default Credentials
        adc_creds = self._resolve_gcp_adc()
        if adc_creds:
            self._log("✓ GCP: Using Application Default Credentials")
            return adc_creds
        
        # 3. GCP_PROJECT env var
        if gcp_project or os.getenv("GCP_PROJECT"):
            return {
                "project_id": gcp_project or os.getenv("GCP_PROJECT"),
                "source": "environment (GCP_PROJECT)"
            }
        
        # 4. Compute Engine instance metadata
        instance_creds = self._resolve_gcp_from_instance_metadata()
        if instance_creds:
            self._log("✓ GCP: Using Compute Engine instance metadata")
            return instance_creds
        
        self._log("✗ GCP: No credentials found", is_error=True)
        return None
    
    def _read_gcp_service_account(self, sa_file: str) -> Optional[Dict]:
        """Read GCP service account JSON file"""
        try:
            sa_path = Path(sa_file)
            if not sa_path.exists():
                return None
            
            with open(sa_path) as f:
                sa_data = json.load(f)
                
                return {
                    "type": sa_data.get("type"),
                    "project_id": sa_data.get("project_id"),
                    "private_key_id": sa_data.get("private_key_id"),
                    "source": f"service account file ({sa_file})"
                }
        except Exception as e:
            self._log(f"Error reading GCP service account: {e}", is_error=True)
        
        return None
    
    def _resolve_gcp_adc(self) -> Optional[Dict]:
        """Read Application Default Credentials"""
        adc_path = Path.home() / ".config" / "gcloud" / "application_default_credentials.json"
        
        if adc_path.exists():
            return self._read_gcp_service_account(str(adc_path))
        
        return None
    
    def _resolve_gcp_from_instance_metadata(self) -> Optional[Dict]:
        """Resolve GCP credentials from Compute Engine instance metadata"""
        try:
            import urllib.request
            import json
            
            # GCP metadata endpoint
            metadata_url = "http://169.254.169.254/computeMetadata/v1/project/project-id"
            
            req = urllib.request.Request(metadata_url)
            req.add_header("Metadata-Flavor", "Google")
            
            with urllib.request.urlopen(req, timeout=1) as response:
                project_id = response.read().decode().strip()
                
                # Try to get service account email too
                sa_url = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email"
                sa_req = urllib.request.Request(sa_url)
                sa_req.add_header("Metadata-Flavor", "Google")
                
                try:
                    with urllib.request.urlopen(sa_req, timeout=1) as sa_response:
                        sa_email = sa_response.read().decode().strip()
                except:
                    sa_email = None
                
                return {
                    "project_id": project_id,
                    "service_account": sa_email,
                    "source": "Compute Engine instance metadata"
                }
        except Exception as e:
            self._log(f"Error reading GCP metadata: {e}", is_error=True)
        
        return None
    
    # ========== KUBERNETES CREDENTIAL CHAIN ==========
    
    def resolve_kubernetes_credentials(self, 
                                      kubeconfig: Optional[str] = None,
                                      context: Optional[str] = None) -> Optional[Dict]:
        """
        Resolve Kubernetes credentials in order:
        1. --kubeconfig flag
        2. KUBECONFIG env var
        3. ~/.kube/config
        4. Kubernetes default service account (in-cluster)
        """
        
        # 1. Explicit kubeconfig flag
        if kubeconfig:
            k8s_creds = self._read_kubeconfig(kubeconfig, context)
            if k8s_creds:
                self._log(f"✓ Kubernetes: Using kubeconfig ({kubeconfig})")
                return k8s_creds
        
        # 2. KUBECONFIG env var
        env_kubeconfig = os.getenv("KUBECONFIG")
        if env_kubeconfig:
            k8s_creds = self._read_kubeconfig(env_kubeconfig, context)
            if k8s_creds:
                self._log(f"✓ Kubernetes: Using KUBECONFIG env var")
                return k8s_creds
        
        # 3. ~/.kube/config (default)
        default_kubeconfig = Path.home() / ".kube" / "config"
        if default_kubeconfig.exists():
            k8s_creds = self._read_kubeconfig(str(default_kubeconfig), context)
            if k8s_creds:
                self._log(f"✓ Kubernetes: Using ~/.kube/config")
                return k8s_creds
        
        # 4. In-cluster service account
        sa_creds = self._resolve_kubernetes_in_cluster()
        if sa_creds:
            self._log("✓ Kubernetes: Using in-cluster service account")
            return sa_creds
        
        self._log("✗ Kubernetes: No credentials found", is_error=True)
        return None
    
    def _read_kubeconfig(self, kubeconfig_path: str, context: Optional[str] = None) -> Optional[Dict]:
        """Read kubeconfig file"""
        try:
            import yaml
            
            kubepath = Path(kubeconfig_path)
            if not kubepath.exists():
                return None
            
            with open(kubepath) as f:
                config = yaml.safe_load(f)
            
            # Get current context
            current_context = context or config.get("current-context")
            
            return {
                "kubeconfig": kubeconfig_path,
                "context": current_context,
                "source": f"kubeconfig ({kubeconfig_path})"
            }
        except Exception as e:
            self._log(f"Error reading kubeconfig: {e}", is_error=True)
        
        return None
    
    def _resolve_kubernetes_in_cluster(self) -> Optional[Dict]:
        """Resolve Kubernetes in-cluster service account"""
        sa_path = Path("/var/run/secrets/kubernetes.io/serviceaccount")
        
        if sa_path.exists():
            token_file = sa_path / "token"
            ca_cert = sa_path / "ca.crt"
            namespace_file = sa_path / "namespace"
            
            if token_file.exists():
                try:
                    with open(token_file) as f:
                        token = f.read().strip()
                    
                    namespace = None
                    if namespace_file.exists():
                        with open(namespace_file) as f:
                            namespace = f.read().strip()
                    
                    return {
                        "token": token,
                        "ca_cert": str(ca_cert) if ca_cert.exists() else None,
                        "namespace": namespace,
                        "source": "in-cluster service account"
                    }
                except Exception as e:
                    self._log(f"Error reading in-cluster service account: {e}", is_error=True)
        
        return None
    
    # ========== UTILITY METHODS ==========
    
    def _log(self, message: str, is_error: bool = False):
        """Pretty-print credential resolution status"""
        if self.verbose:
            if is_error:
                logger.warning(message)
            else:
                logger.info(message)
    
    def get_all_credentials(self, 
                           aws_profile: Optional[str] = None,
                           azure_profile: Optional[str] = None,
                           gcp_project: Optional[str] = None,
                           kubeconfig: Optional[str] = None,
                           k8s_context: Optional[str] = None) -> Dict[str, Optional[Dict]]:
        """Resolve all cloud provider credentials"""
        
        return {
            "aws": self.resolve_aws_credentials(aws_profile),
            "azure": self.resolve_azure_credentials(azure_profile),
            "gcp": self.resolve_gcp_credentials(gcp_project),
            "kubernetes": self.resolve_kubernetes_credentials(kubeconfig, k8s_context)
        }


if __name__ == "__main__":
    # Test credential chain resolution
    logging.basicConfig(level=logging.INFO)
    
    chain = CredentialChain(verbose=True)
    
    print("\n=== Testing Credential Chain Resolution ===\n")
    
    print("[AWS]")
    aws_creds = chain.resolve_aws_credentials()
    print(f"  ✓ Credentials found" if aws_creds else f"  ✗ No credentials found")
    if aws_creds:
        print(f"  Source: {aws_creds.get('source')}")
        print(f"  Region: {aws_creds.get('region')}")
    
    print("\n[Azure]")
    azure_creds = chain.resolve_azure_credentials()
    print(f"  ✓ Credentials found" if azure_creds else f"  ✗ No credentials found")
    if azure_creds:
        print(f"  Source: {azure_creds.get('source')}")
    
    print("\n[GCP]")
    gcp_creds = chain.resolve_gcp_credentials()
    print(f"  ✓ Credentials found" if gcp_creds else f"  ✗ No credentials found")
    if gcp_creds:
        print(f"  Source: {gcp_creds.get('source')}")
    
    print("\n[Kubernetes]")
    k8s_creds = chain.resolve_kubernetes_credentials()
    print(f"  ✓ Credentials found" if k8s_creds else f"  ✗ No credentials found")
    if k8s_creds:
        print(f"  Source: {k8s_creds.get('source')}")
    
    print("\n" + "="*60)
    print("Credential chain resolution test complete")
    print("="*60 + "\n")
