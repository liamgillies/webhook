resource "google_storage_bucket" "test-bucket-sdfadsfsafd" {
  location = "us-east1"
  name     = "test-zxcvzx"
}

data "archive_file" "webhook-trigger" {
  type = "zip"
  source_dir = "${path.module}/webhook"
  output_path = "${path.module}/webhook.zip"
}

resource "google_storage_bucket_object" "source_code" {
  bucket = google_storage_bucket.test-bucket-sdfadsfsafd.name
  name   = "usermapper-github-webhook"
  source = "webhook.zip"
}

resource "google_cloudfunctions_function" "usermapper-github-webhook" {
  name = "usermapper-github-webhook"
  description = "runs WebhookHandler"
  runtime = "go119"

  lifecycle {
    replace_triggered_by  = [
      google_storage_bucket_object.source_code.md5hash
    ]
  }

#  ingress_settings = "ALLOW_INTERNAL_AND_GCLB"

  trigger_http = true

  max_instances = 1
  available_memory_mb = 256

  source_archive_bucket = google_storage_bucket.test-bucket-sdfadsfsafd.name
  source_archive_object = google_storage_bucket_object.source_code.name
  entry_point = "WebhookHandler"
}

resource "google_cloudfunctions_function_iam_binding" "binding" {
  project = google_cloudfunctions_function.usermapper-github-webhook.project
  region = google_cloudfunctions_function.usermapper-github-webhook.region
  cloud_function = google_cloudfunctions_function.usermapper-github-webhook.name
  role = "roles/cloudfunctions.invoker"
  members = [
    "allUsers",
  ]
}

#module "cloud-armor" {
#  source = "GoogleCloudPlatform/cloud-armor/google"
#  name   = "github-webhook-armor"
#  project_id = local.project_id
#
#  default_rule_action = "deny(403)"
#
##  allow_path_token_header = {
##    action      = "allow"
##    priority    = 25
##    description = "Allow path and token match with addition of header"
##
##    expression = <<-EOT
##        request.path.matches('/login.html') && token.recaptcha_session.score < 0.2
##      EOT
##
##    header_action = [
##      {
##        header_name  = "reCAPTCHA-Warning"
##        header_value = "high"
##      },
##      {
##        header_name  = "X-Resource"
##        header_value = "test"
##      }
##    ]
##
##  }
#}

resource "google_compute_managed_ssl_certificate" "usermapper-ssl" {
  name = "my-lb-cert"

  managed {
    domains = ["usermapperwh.dev.crdb.dev."]
  }
}

# IP address for wiki.crdb.io.
resource "google_compute_global_address" "usermapper-address" {
  name = "usermapperwh"
}

resource "google_compute_region_network_endpoint_group" "usermapper-function_neg" {
  name                  = "usermapper-neg"
  network_endpoint_type = "SERVERLESS"
  region                = "us-east1"
  cloud_function {
    function = google_cloudfunctions_function.usermapper-github-webhook.name
  }
}

// Backend service for NEG
resource "google_compute_backend_service" "usermapper-backend" {
  name      = "backend-default"
  protocol  = "HTTPS"
  backend {
    group = google_compute_region_network_endpoint_group.usermapper-function_neg.id
  }
}

resource "google_compute_url_map" "usermapperwd-dev-crdb-dev" {
  name            = "usermapper-url-map-target-proxy"
  description     = "url map for usermapper"
  default_service = google_compute_backend_service.usermapper-backend.id

  host_rule {
    hosts        = ["usermapperwh.dev.crdb.dev"]
    path_matcher = "allpaths"
  }

  path_matcher {
    name            = "allpaths"
    default_service = google_compute_backend_service.usermapper-backend.id

    path_rule {
      paths   = ["/*"]
      service = google_compute_backend_service.usermapper-backend.id
    }
  }
}

resource "google_compute_target_https_proxy" "usermapper-proxy" {
  name             = "usermapper-target-proxy"
  description      = "https proxy for usermapperwh.dev.crdb.dev"
  url_map          = google_compute_url_map.usermapperwd-dev-crdb-dev.id
  ssl_certificates = [google_compute_managed_ssl_certificate.usermapper-ssl.name]
}

resource "google_compute_global_forwarding_rule" "usermapper-forward-https" {
  name       = "usermapper-https"
  ip_address = google_compute_global_address.usermapper-address.name
  target     = google_compute_target_https_proxy.usermapper-proxy.id
  port_range = 443
}

#
#resource "google_compute_url_map" "usermapper-url-map" {
#  name            = "url-map-target-proxy"
#  description     = "a description"
#  default_service = google_compute_backend_service.usermapper-backend.id
#
#  host_rule {
#    hosts        = ["34.120.166.182"]
#    path_matcher = "allpaths"
#  }
#
#  path_matcher {
#    name            = "allpaths"
#    default_service = google_compute_backend_service.usermapper-backend.id
#
#    path_rule {
#      paths   = ["/*"]
#      service = google_compute_backend_service.usermapper-backend.id
#    }
#  }
#}
#
#resource "google_compute_target_http_proxy" "cockroachdb-com" {
#  name        = "target-proxy"
#  description = "a description"
#  url_map     = google_compute_url_map.usermapper-url-map.id
#}
#
#module "lb-http" {
#  source            = "GoogleCloudPlatform/lb-http/google"
#  project           = local.project_id
#  name              = "my-lb"
#  managed_ssl_certificate_domains = ["usermapperwh.dev.crdb.dev"]
#  ssl                             = true
#  https_redirect                  = true
#
#  backends = {
#    default = {
#      # List your serverless NEGs, VMs, or buckets as backends
#      groups = [
#        {
#          group = google_compute_region_network_endpoint_group.usermapper-function_neg.id
#        }
#      ]
#
#      enable_cdn = false
#
#      log_config = {
#        enable      = true
#        sample_rate = 1.0
#      }
#
#      iap_config = {
#        enable               = false
#        oauth2_client_id     = null
#        oauth2_client_secret = null
#      }
#
#      description             = null
#      custom_request_headers  = null
#      security_policy         = null
#    }
#  }
#}