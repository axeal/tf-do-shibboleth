provider "kubernetes" {
}

resource "kubernetes_namespace" "shibboleth" {
  metadata {
    name = "shibboleth"
  }
}

resource "kubernetes_config_map" "shibboleth_conf" {
  metadata {
    namespace = "shibboleth"
    name      = "shibboleth-conf"
  }

  data = {
    "attribute-filter.xml"   = "${file("${path.module}/files/conf/attribute-filter.xml")}"
    "attribute-resolver.xml" = "${file("${path.module}/files/conf/attribute-resolver.xml")}"
    "idp.properties" = templatefile(
      "${"${path.module}/files/conf/idp.properties.tmpl"}",
      {
        domain = var.domain,
        fqdn   = "${var.host}.${var.domain}"
      }
    ),
    "ldap.properties"        = "${file("${path.module}/files/conf/ldap.properties")}"
    "login.conf"             = "${file("${path.module}/files/conf/login.conf")}"
    "metadata-providers.xml" = "${file("${path.module}/files/conf/metadata-providers.xml")}"
  }
}

resource "kubernetes_config_map" "shibboleth_credentials" {
  metadata {
    namespace = "shibboleth"
    name      = "shibboleth-credentials"
  }

  data = {
    "idp-backchannel.crt" = tls_self_signed_cert.idp_backchannel.cert_pem
    "idp-backchannel.key" = tls_private_key.idp_backchannel.private_key_pem
    "idp-browser.crt"     = tls_self_signed_cert.idp_browser.cert_pem
    "idp-browser.key"     = tls_private_key.idp_browser.private_key_pem
    "idp-encryption.crt"  = tls_self_signed_cert.idp_encryption.cert_pem
    "idp-encryption.key"  = tls_private_key.idp_encryption.private_key_pem
    "idp-signing.crt"     = tls_self_signed_cert.idp_signing.cert_pem
    "idp-signing.key"     = tls_private_key.idp_signing.private_key_pem
    "sealer.kver"         = "${file("${path.module}/files/credentials/sealer.kver")}"
  }

  binary_data = {
    "sealer.jks" = "${filebase64("${path.module}/files/credentials/sealer.jks")}"
  }
}

resource "kubernetes_config_map" "shibboleth_metadata" {
  metadata {
    namespace = "shibboleth"
    name      = "shibboleth-metadata"
  }

  data = {
    "idp-metadata.xml" = templatefile(
      "${"${path.module}/files/metadata/idp-metadata.xml.tmpl"}",
      {
        domain           = var.domain,
        fqdn             = "${var.host}.${var.domain}",
        encryption_cert  = trimsuffix(trimprefix(tls_self_signed_cert.idp_encryption.cert_pem, "-----BEGIN CERTIFICATE-----\n"), "\n-----END CERTIFICATE-----\n"),
        signing_cert     = trimsuffix(trimprefix(tls_self_signed_cert.idp_signing.cert_pem, "-----BEGIN CERTIFICATE-----\n"), "\n-----END CERTIFICATE-----\n")
        backchannel_cert = trimsuffix(trimprefix(tls_self_signed_cert.idp_backchannel.cert_pem, "-----BEGIN CERTIFICATE-----\n"), "\n-----END CERTIFICATE-----\n")
      }
    ),
    "rancher.xml" = templatefile(
      "${"${path.module}/files/metadata/rancher.xml.tmpl"}",
      {
        cert        = replace(trimsuffix(trimprefix(tls_self_signed_cert.rancher.cert_pem, "-----BEGIN CERTIFICATE-----\n"), "\n-----END CERTIFICATE-----\n"), "\n", ""),
        rancher_url = var.rancher_url
      }
    )
  }
}

resource "kubernetes_deployment" "ldap" {
  metadata {
    name      = "ldap"
    namespace = "shibboleth"
    labels = {
      app = "ldap"
    }
  }
  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "ldap"
      }
    }

    template {
      metadata {
        labels = {
          app = "ldap"
        }
      }

      spec {
        container {
          image = "osixia/openldap:1.4.0"
          name  = "ldap"
          port {
            container_port = 389
            host_port      = 389
          }
          port {
            container_port = 636
            host_port      = 636
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "ldap" {
  metadata {
    name      = "ldap"
    namespace = "shibboleth"
  }
  spec {
    selector = {
      app = "ldap"
    }
    port {
      port        = 389
      target_port = 389
    }

    type = "ClusterIP"
  }
}

resource "kubernetes_deployment" "ldap_admin" {
  metadata {
    name      = "ldap-admin"
    namespace = "shibboleth"
    labels = {
      app = "ldap-admin"
    }
  }
  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "ldap-admin"
      }
    }

    template {
      metadata {
        labels = {
          app = "ldap-admin"
        }
      }

      spec {
        container {
          image = "osixia/phpldapadmin:0.9.0"
          name  = "ldap-admin"
          port {
            container_port = 443
          }
          env {
            name  = "PHPLDAPADMIN_LDAP_HOSTS"
            value = "ldap"
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "ldap_admin" {
  metadata {
    name      = "ldap-admin"
    namespace = "shibboleth"
  }
  spec {
    selector = {
      app = "ldap-admin"
    }
    port {
      port        = 443
      target_port = 443
    }

    type = "ClusterIP"
  }
}

resource "kubernetes_ingress" "shibboleth" {
  metadata {
    name      = "shibboleth"
    namespace = "shibboleth"
    annotations = {
      "nginx.ingress.kubernetes.io/backend-protocol" = "HTTPS"
    }
  }

  spec {
    rule {
      http {
        path {
          backend {
            service_name = "shibboleth"
            service_port = 443
          }

          path = "/idp/"
        }

        path {
          backend {
            service_name = "ldap-admin"
            service_port = 443
          }

          path = "/"
        }
      }
    }

    tls {
      hosts = [
        "${var.host}.${var.domain}",
      ]
    }
  }
}

resource "kubernetes_deployment" "shibboleth" {
  metadata {
    name      = "shibboleth"
    namespace = "shibboleth"
    labels = {
      app = "shibboleth"
    }
  }
  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "shibboleth"
      }
    }

    template {
      metadata {
        labels = {
          app = "shibboleth"
        }
      }

      spec {
        container {
          image = "unicon/shibboleth-idp:3.4.3"
          name  = "shibboleth"
          port {
            container_port = 4443
          }
          env {
            name  = "JETTY_BROWSER_SSL_KEYSTORE_PASSWORD"
            value = "password"
          }
          env {
            name  = "JETTY_BACKCHANNEL_SSL_KEYSTORE_PASSWORD"
            value = "password"
          }
          volume_mount {
            name       = "conf"
            mount_path = "/opt/shibboleth-idp/conf/attribute-filter.xml"
            sub_path   = "attribute-filter.xml"
          }
          volume_mount {
            name       = "conf"
            mount_path = "/opt/shibboleth-idp/conf/attribute-resolver.xml"
            sub_path   = "attribute-resolver.xml"
          }
          volume_mount {
            name       = "conf"
            mount_path = "/opt/shibboleth-idp/conf/ldap.properties"
            sub_path   = "ldap.properties"
          }
          volume_mount {
            name       = "conf"
            mount_path = "/opt/shibboleth-idp/conf/idp.properties"
            sub_path   = "idp.properties"
          }
          volume_mount {
            name       = "conf"
            mount_path = "/opt/shibboleth-idp/conf/login.conf"
            sub_path   = "login.conf"
          }
          volume_mount {
            name       = "conf"
            mount_path = "/opt/shibboleth-idp/conf/metadata-providers.xml"
            sub_path   = "metadata-providers.xml"
          }
          volume_mount {
            name       = "metadata"
            mount_path = "/opt/shibboleth-idp/metadata"
          }
          volume_mount {
            name       = "credentials"
            mount_path = "/opt/shibboleth-idp/credentials/idp-backchannel.crt"
            sub_path   = "idp-backchannel.crt"
          }
          volume_mount {
            name       = "credentials"
            mount_path = "/opt/shibboleth-idp/credentials/idp-encryption.crt"
            sub_path   = "idp-encryption.crt"
          }
          volume_mount {
            name       = "credentials"
            mount_path = "/opt/shibboleth-idp/credentials/idp-encryption.key"
            sub_path   = "idp-encryption.key"
          }
          volume_mount {
            name       = "credentials"
            mount_path = "/opt/shibboleth-idp/credentials/idp-signing.crt"
            sub_path   = "idp-signing.crt"
          }
          volume_mount {
            name       = "credentials"
            mount_path = "/opt/shibboleth-idp/credentials/idp-signing.key"
            sub_path   = "idp-signing.key"
          }
          volume_mount {
            name       = "credentials"
            mount_path = "/opt/shibboleth-idp/credentials/sealer.kver"
            sub_path   = "sealer.kver"
          }
          volume_mount {
            name       = "p12-certs"
            mount_path = "/opt/shibboleth-idp/credentials/idp-backchannel.p12"
            sub_path   = "idp-backchannel.p12"
          }
          volume_mount {
            name       = "p12-certs"
            mount_path = "/opt/shibboleth-idp/credentials/idp-browser.p12"
            sub_path   = "idp-browser.p12"
          }
          volume_mount {
            name       = "sealer"
            mount_path = "/opt/shibboleth-idp/credentials/sealer.jks"
            sub_path   = "sealer.jks"
          }
        }
        init_container {
          name  = "openssl-backend"
          image = "frapsoft/openssl"
          args = [
            "pkcs12",
            "-export",
            "-name",
            "idp-backchannel.p12",
            "-out",
            "/certs/idp-backchannel.p12",
            "-inkey",
            "/credentials/idp-backchannel.key",
            "-in",
            "/credentials/idp-backchannel.crt",
            "-password",
            "pass:password"
          ]
          volume_mount {
            name       = "p12-certs"
            mount_path = "/certs"
          }
          volume_mount {
            name       = "credentials"
            mount_path = "/credentials"
          }
        }
        init_container {
          name  = "openssl-browser"
          image = "frapsoft/openssl"
          args = [
            "pkcs12",
            "-export",
            "-name",
            "idp-browser.p12",
            "-out",
            "/certs/idp-browser.p12",
            "-inkey",
            "/credentials/idp-browser.key",
            "-in",
            "/credentials/idp-browser.crt",
            "-password",
            "pass:password"
          ]
          volume_mount {
            name       = "p12-certs"
            mount_path = "/certs"
          }
          volume_mount {
            name       = "credentials"
            mount_path = "/credentials"
          }
        }
        init_container {
          name  = "keytool"
          image = "joostdecock/keytool"
          args = [
            "-genseckey",
            "-keystore",
            "/keystore/sealer.jks",
            "-storepass",
            "password",
            "-storetype",
            "JCEKS",
            "-alias",
            "secret1",
            "-keypass",
            "password",
            "-keysize",
            "128",
            "-keyalg",
            "AES"
          ]
          volume_mount {
            name       = "sealer"
            mount_path = "/keystore"
          }
        }
        volume {
          name = "conf"
          config_map {
            name = "shibboleth-conf"
          }
        }
        volume {
          name = "credentials"
          config_map {
            name = "shibboleth-credentials"
          }
        }
        volume {
          name = "metadata"
          config_map {
            name = "shibboleth-metadata"
          }
        }
        volume {
          name = "p12-certs"
          empty_dir {}
        }
        volume {
          name = "sealer"
          empty_dir {}
        }
      }
    }
  }
}

resource "kubernetes_service" "shibboleth" {
  metadata {
    name      = "shibboleth"
    namespace = "shibboleth"
  }
  spec {
    selector = {
      app = "shibboleth"
    }
    port {
      port        = 443
      target_port = 4443
    }

    type = "ClusterIP"
  }
}

resource "local_file" "idp_metadata" {
  content = templatefile(
    "${"${path.module}/files/idp-metadata.xml.tmpl"}",
    {
      domain          = var.domain,
      fqdn            = "${var.host}.${var.domain}",
      encryption_cert = trimsuffix(trimprefix(tls_self_signed_cert.idp_encryption.cert_pem, "-----BEGIN CERTIFICATE-----\n"), "\n-----END CERTIFICATE-----\n"),
      signing_cert    = trimsuffix(trimprefix(tls_self_signed_cert.idp_signing.cert_pem, "-----BEGIN CERTIFICATE-----\n"), "\n-----END CERTIFICATE-----\n")
    }
  )
  filename = "${path.module}/idp-metadata.xml"
}

resource "tls_private_key" "idp_backchannel" {
  algorithm = "RSA"
  rsa_bits  = "3072"
}

resource "tls_self_signed_cert" "idp_backchannel" {
  key_algorithm   = "RSA"
  private_key_pem = tls_private_key.idp_backchannel.private_key_pem

  subject {
    common_name = "${var.host}.${var.domain}"
  }

  dns_names = [
    "${var.host}.${var.domain}"
  ]

  uris = [
    "https://${var.host}.${var.domain}/idp/shibboleth"
  ]

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]

  validity_period_hours = 8760
  set_subject_key_id    = true
}


resource "tls_private_key" "idp_browser" {
  algorithm = "RSA"
  rsa_bits  = "2048"
}

resource "tls_self_signed_cert" "idp_browser" {
  key_algorithm   = "RSA"
  private_key_pem = tls_private_key.idp_browser.private_key_pem

  subject {
    common_name = "${var.host}.${var.domain}"
  }

  dns_names = [
    "${var.host}.${var.domain}"
  ]

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]

  validity_period_hours = 8760
  set_subject_key_id    = true
}

resource "tls_private_key" "idp_encryption" {
  algorithm = "RSA"
  rsa_bits  = "3072"
}

resource "tls_self_signed_cert" "idp_encryption" {
  key_algorithm   = "RSA"
  private_key_pem = tls_private_key.idp_encryption.private_key_pem

  subject {
    common_name = "${var.host}.${var.domain}"
  }

  dns_names = [
    "${var.host}.${var.domain}"
  ]

  uris = [
    "https://${var.host}.${var.domain}/idp/shibboleth"
  ]

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]

  validity_period_hours = 8760
  set_subject_key_id    = true
}

resource "tls_private_key" "idp_signing" {
  algorithm = "RSA"
  rsa_bits  = "3072"
}

resource "tls_self_signed_cert" "idp_signing" {
  key_algorithm   = "RSA"
  private_key_pem = tls_private_key.idp_signing.private_key_pem

  subject {
    common_name = "${var.host}.${var.domain}"
  }

  dns_names = [
    "${var.host}.${var.domain}"
  ]

  uris = [
    "https://${var.host}.${var.domain}/idp/shibboleth"
  ]

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]

  validity_period_hours = 8760
  set_subject_key_id    = true
}

resource "tls_private_key" "rancher" {
  algorithm = "RSA"
  rsa_bits  = "3072"
}

resource "tls_self_signed_cert" "rancher" {
  key_algorithm   = "RSA"
  private_key_pem = tls_private_key.rancher.private_key_pem

  subject {
    common_name = "${var.host}.${var.domain}"
  }

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]

  validity_period_hours = 8760
  set_subject_key_id    = true
}

resource "local_file" "rancher_key" {
  content  = tls_private_key.rancher.private_key_pem
  filename = "${path.module}/rancher.key"
}

resource "local_file" "rancher_cert" {
  content  = tls_self_signed_cert.rancher.cert_pem
  filename = "${path.module}/rancher.crt"
}