terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.64.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.2.0"
    }
  }
}

provider "google" {
  project = local.project_id
  region  = var.region
}
