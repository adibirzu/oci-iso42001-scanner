#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Build OCI Resource Manager Stack zip
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/stack-build"
OUTPUT="$PROJECT_DIR/iso42001-scanner-stack.zip"

echo "Building OCI Stack from $PROJECT_DIR..."

# Clean
rm -rf "$BUILD_DIR" "$OUTPUT"
mkdir -p "$BUILD_DIR"

# Copy Terraform files (required at root of zip for Resource Manager)
cp "$SCRIPT_DIR/terraform/main.tf" "$BUILD_DIR/"
cp "$SCRIPT_DIR/terraform/schema.yaml" "$BUILD_DIR/"
cp "$SCRIPT_DIR/terraform/cloud-init.sh" "$BUILD_DIR/"

# Build zip
cd "$BUILD_DIR"
zip -r "$OUTPUT" .

# Cleanup
rm -rf "$BUILD_DIR"

echo ""
echo "Stack built: $OUTPUT"
echo "Size: $(du -h "$OUTPUT" | cut -f1)"
echo ""
echo "Deploy via OCI Console:"
echo "  1. Go to Resource Manager → Stacks → Create Stack"
echo "  2. Upload $OUTPUT"
echo "  3. Fill in variables and Apply"
echo ""
echo "Deploy via CLI:"
echo "  oci resource-manager stack create \\"
echo "    --compartment-id <COMPARTMENT_OCID> \\"
echo "    --config-source $OUTPUT \\"
echo "    --display-name 'ISO 42001 AI Compliance Scanner'"
