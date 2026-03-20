# ═══════════════════════════════════════════════════════════════
# ISO 42001 AI Compliance Scanner — OCI Stack
# Fully autonomous deployment with Instance Principal authentication
# ═══════════════════════════════════════════════════════════════

terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}

# ── Variables ──

variable "compartment_ocid" {
  type = string
}

variable "tenancy_ocid" {
  type = string
}

variable "region" {
  type = string
}

variable "instance_shape" {
  type    = string
  default = "VM.Standard.E4.Flex"
}

variable "instance_ocpus" {
  type    = number
  default = 1
}

variable "instance_memory_gb" {
  type    = number
  default = 8
}

variable "ssh_public_key" {
  type = string
}

# Networking

variable "create_vcn" {
  type    = bool
  default = true
}

variable "vcn_cidr" {
  type    = string
  default = "10.42.0.0/16"
}

variable "subnet_cidr" {
  type    = string
  default = "10.42.1.0/24"
}

variable "existing_subnet_ocid" {
  type        = string
  default     = ""
  description = "OCID of existing subnet (required when create_vcn = false)"
}

# Scanner configuration

variable "scanner_port" {
  type    = number
  default = 8080
}

variable "enable_daily_scan" {
  type    = bool
  default = true
}

variable "scan_time_utc" {
  type    = string
  default = "02:00"
}

# Source repo

variable "repo_url" {
  type    = string
  default = "https://github.com/adibirzu/oci-iso42001-scanner.git"
}

variable "repo_branch" {
  type    = string
  default = "main"
}

# ── Data Sources ──

data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

data "oci_core_images" "ol8" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Oracle Linux"
  operating_system_version = "8"
  shape                    = var.instance_shape
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

# ── Networking (optional — only when create_vcn = true) ──

resource "oci_core_vcn" "scanner_vcn" {
  count          = var.create_vcn ? 1 : 0
  compartment_id = var.compartment_ocid
  cidr_blocks    = [var.vcn_cidr]
  display_name   = "iso42001-scanner-vcn"
  dns_label      = "iso42001"
}

resource "oci_core_internet_gateway" "igw" {
  count          = var.create_vcn ? 1 : 0
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.scanner_vcn[0].id
  display_name   = "iso42001-igw"
}

resource "oci_core_route_table" "rt" {
  count          = var.create_vcn ? 1 : 0
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.scanner_vcn[0].id
  display_name   = "iso42001-rt"

  route_rules {
    network_entity_id = oci_core_internet_gateway.igw[0].id
    destination       = "0.0.0.0/0"
  }
}

resource "oci_core_security_list" "sl" {
  count          = var.create_vcn ? 1 : 0
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.scanner_vcn[0].id
  display_name   = "iso42001-sl"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }

  ingress_security_rules {
    source   = "0.0.0.0/0"
    protocol = "6" # TCP
    tcp_options {
      min = 22
      max = 22
    }
  }

  ingress_security_rules {
    source   = "0.0.0.0/0"
    protocol = "6"
    tcp_options {
      min = var.scanner_port
      max = var.scanner_port
    }
  }
}

resource "oci_core_subnet" "scanner_subnet" {
  count             = var.create_vcn ? 1 : 0
  compartment_id    = var.compartment_ocid
  vcn_id            = oci_core_vcn.scanner_vcn[0].id
  cidr_block        = var.subnet_cidr
  display_name      = "iso42001-scanner-subnet"
  dns_label         = "scanner"
  route_table_id    = oci_core_route_table.rt[0].id
  security_list_ids = [oci_core_security_list.sl[0].id]
}

locals {
  subnet_id = var.create_vcn ? oci_core_subnet.scanner_subnet[0].id : var.existing_subnet_ocid
}

# ── IAM: Dynamic Group + Policy for Instance Principal ──

resource "oci_identity_dynamic_group" "scanner_dg" {
  compartment_id = var.tenancy_ocid
  name           = "iso42001-scanner-instances"
  description    = "Dynamic group for ISO 42001 compliance scanner instances"
  matching_rule  = "ALL {instance.compartment.id = '${var.compartment_ocid}'}"
}

resource "oci_identity_policy" "scanner_policy" {
  compartment_id = var.tenancy_ocid
  name           = "iso42001-scanner-policy"
  description    = "Allow ISO 42001 scanner to read tenancy resources for compliance checks"
  statements = [
    "Allow dynamic-group ${oci_identity_dynamic_group.scanner_dg.name} to inspect all-resources in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.scanner_dg.name} to read all-resources in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.scanner_dg.name} to use cloud-guard-config in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.scanner_dg.name} to read data-safe-family in tenancy",
    "Allow dynamic-group ${oci_identity_dynamic_group.scanner_dg.name} to read ai-service-family in tenancy",
  ]
}

# ── Compute Instance ──

resource "oci_core_instance" "scanner" {
  compartment_id      = var.compartment_ocid
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  shape               = var.instance_shape
  display_name        = "iso42001-scanner"

  shape_config {
    ocpus         = var.instance_ocpus
    memory_in_gbs = var.instance_memory_gb
  }

  source_details {
    source_type = "image"
    source_id   = data.oci_core_images.ol8.images[0].id
  }

  create_vnic_details {
    subnet_id        = local.subnet_id
    assign_public_ip = true
    display_name     = "iso42001-scanner-vnic"
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data = base64encode(templatefile("${path.module}/cloud-init.sh", {
      tenancy_ocid = var.tenancy_ocid
      scanner_port = var.scanner_port
      enable_cron  = var.enable_daily_scan
      scan_time    = var.scan_time_utc
      repo_url     = var.repo_url
      repo_branch  = var.repo_branch
    }))
  }

  freeform_tags = {
    "Purpose"   = "ISO42001-AI-Compliance-Scanner"
    "Framework" = "ISO/IEC 42001:2023"
    "ManagedBy" = "Terraform"
  }

  depends_on = [
    oci_identity_dynamic_group.scanner_dg,
    oci_identity_policy.scanner_policy,
  ]
}

# ── Outputs ──

output "scanner_public_ip" {
  value = oci_core_instance.scanner.public_ip
}

output "scanner_api_url" {
  value = "http://${oci_core_instance.scanner.public_ip}:${var.scanner_port}"
}

output "scanner_health_check" {
  value = "curl http://${oci_core_instance.scanner.public_ip}:${var.scanner_port}/health"
}

output "dynamic_group_ocid" {
  value = oci_identity_dynamic_group.scanner_dg.id
}

output "instance_ocid" {
  value = oci_core_instance.scanner.id
}
