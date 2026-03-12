#!/usr/bin/env bash
# v-19 Setup Script
# Installs v-19 and verifies cloud credentials

set -e

echo "=========================================="
echo "  v-19 Scanner — Setup"
echo "=========================================="
echo ""

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 9 ]); then
    echo "ERROR: Python 3.9+ required. Found: $PYTHON_VERSION"
    exit 1
fi
echo "[OK] Python $PYTHON_VERSION"

# Install v-19
echo ""
echo "Installing v-19..."
pip install -e . --quiet
echo "[OK] v-19 installed"

# Check v-19 version
V19_VERSION=$(v-19 --version 2>&1)
echo "[OK] $V19_VERSION"

# Check cloud credentials
echo ""
echo "Checking cloud credentials..."

# AWS
if aws sts get-caller-identity &>/dev/null; then
    AWS_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
    echo "[OK] AWS: Account $AWS_ID"
else
    echo "[--] AWS: No credentials (optional)"
fi

# Azure
if az account show &>/dev/null; then
    AZ_SUB=$(az account show --query name --output tsv 2>/dev/null)
    echo "[OK] Azure: $AZ_SUB"
else
    echo "[--] Azure: No credentials (optional)"
fi

# GCP
if gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1 | grep -q '@'; then
    GCP_ACCT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1)
    echo "[OK] GCP: $GCP_ACCT"
else
    echo "[--] GCP: No credentials (optional)"
fi

# Kubernetes
if kubectl cluster-info &>/dev/null; then
    K8S_CTX=$(kubectl config current-context 2>/dev/null)
    echo "[OK] K8s: $K8S_CTX"
else
    echo "[--] K8s: No credentials (optional)"
fi

echo ""
echo "=========================================="
echo "  Setup complete. Run: v-19 analyze"
echo "=========================================="
