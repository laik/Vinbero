terraform {
  required_version = ">= 0.12.5"
  required_providers {
    sakuracloud = {
      source = "sacloud/sakuracloud"

      # We recommend pinning to the specific version of the SakuraCloud Provider you're using
      # since new versions are released frequently
      version = "~> 2"
    }
  }
}
# Configure the SakuraCloud Provider
provider "sakuracloud" {
}

# ubuntu archive
data sakuracloud_archive "ubuntu-archive" {
  filter {
    tags = ["ubuntu", "2004", "5.8"]
  }
}

# pub key
resource sakuracloud_ssh_key_gen "key" {
  name = "pubkey"

  provisioner "local-exec" {
    command = "echo \"${self.private_key}\" > id_rsa; chmod 0600 id_rsa"
  }

  provisioner "local-exec" {
    when    = destroy
    command = "rm -f id_rsa"
  }
}

# switch
resource sakuracloud_switch "h1-rt1-switch" {
  name = "h1-rt1-switch"
}
resource sakuracloud_switch "rt1-rt2-switch" {
  name = "rt1-rt2-switch"
}
resource sakuracloud_switch "rt2-rt3-switch" {
  name = "rt2-rt3-switch"
}
resource sakuracloud_switch "rt3-h2-switch" {
  name = "rt3-h2-switch"
}

# disks
resource sakuracloud_disk "host-01-disk" {
  name              = "host-01"
  source_archive_id = data.sakuracloud_archive.ubuntu-archive.id
  size              = 100
  tags              = ["srv6"]
}
resource sakuracloud_disk "host-02-disk" {
  name              = "host-02"
  source_archive_id = data.sakuracloud_archive.ubuntu-archive.id
  size              = 100
  tags              = ["srv6"]
}
resource sakuracloud_disk "router-01-disk" {
  name              = "router-01"
  source_archive_id = data.sakuracloud_archive.ubuntu-archive.id
  size              = 100
  tags              = ["srv6"]
}
resource sakuracloud_disk "router-02-disk" {
  name              = "router-02"
  source_archive_id = data.sakuracloud_archive.ubuntu-archive.id
  size              = 100
  tags              = ["srv6"]
}
resource sakuracloud_disk "router-03-disk" {
  name              = "router-03"
  source_archive_id = data.sakuracloud_archive.ubuntu-archive.id
  size              = 100
  tags              = ["srv6"]
}

# servers
resource sakuracloud_server "host-01-server" {
  name   = "host-01"
  core   = 4
  memory = 4
  disks  = [sakuracloud_disk.host-01-disk.id]
  tags   = ["@nic-double-queue", "srv6"]

  network_interface {
    upstream = "shared"
  }
  network_interface {
    upstream = sakuracloud_switch.h1-rt1-switch.id
  }
  disk_edit_parameter {
    hostname        = "host-01"
    ssh_key_ids     = [sakuracloud_ssh_key_gen.key.id]
    password        = "PUT_YOUR_PASSWORD_HERE"
    disable_pw_auth = "true"
  }
}

resource sakuracloud_server "router-01-server" {
  name   = "router-01"
  core   = 4
  memory = 4
  disks  = [sakuracloud_disk.router-01-disk.id]
  tags   = ["@nic-double-queue", "srv6"]
  network_interface {
    upstream = "shared"
  }
  network_interface {
    upstream = sakuracloud_switch.h1-rt1-switch.id
  }
  network_interface {
    upstream = sakuracloud_switch.rt1-rt2-switch.id
  }
  disk_edit_parameter {
    hostname        = "router-01"
    ssh_key_ids     = [sakuracloud_ssh_key_gen.key.id]
    password        = "PUT_YOUR_PASSWORD_HERE"
    disable_pw_auth = "true"
  }
}

resource sakuracloud_server "router-02-server" {
  name   = "router-02"
  core   = 4
  memory = 4
  disks  = [sakuracloud_disk.router-02-disk.id]
  tags   = ["@nic-double-queue", "srv6"]
  network_interface {
    upstream = "shared"
  }
  network_interface {
    upstream = sakuracloud_switch.rt1-rt2-switch.id
  }
  network_interface {
    upstream = sakuracloud_switch.rt2-rt3-switch.id
  }
  disk_edit_parameter {
    hostname        = "router-02"
    ssh_key_ids     = [sakuracloud_ssh_key_gen.key.id]
    password        = "PUT_YOUR_PASSWORD_HERE"
    disable_pw_auth = "true"
  }
}

resource sakuracloud_server "router-03-server" {
  name   = "router-03"
  core   = 4
  memory = 4
  disks  = [sakuracloud_disk.router-03-disk.id]
  tags   = ["@nic-double-queue", "srv6"]
  network_interface {
    upstream = "shared"
  }
  network_interface {
    upstream = sakuracloud_switch.rt2-rt3-switch.id
  }
  network_interface {
    upstream = sakuracloud_switch.rt3-h2-switch.id
  }
  disk_edit_parameter {
    hostname        = "router-03"
    ssh_key_ids     = [sakuracloud_ssh_key_gen.key.id]
    password        = "PUT_YOUR_PASSWORD_HERE"
    disable_pw_auth = "true"
  }
}
resource sakuracloud_server "host-02-server" {
  name   = "host-02"
  core   = 4
  memory = 4
  disks  = [sakuracloud_disk.host-02-disk.id]
  tags   = ["@nic-double-queue", "srv6"]

  network_interface {
    upstream = "shared"
  }
  network_interface {
    upstream = sakuracloud_switch.rt3-h2-switch.id
  }
  disk_edit_parameter {
    hostname        = "host-02"
    ssh_key_ids     = [sakuracloud_ssh_key_gen.key.id]
    password        = "PUT_YOUR_PASSWORD_HERE"
    disable_pw_auth = "true"
  }
}

output "host-01" {
  value = "${sakuracloud_server.host-01-server.ip_address}"
}

output "router-01" {
  value = "${sakuracloud_server.router-01-server.ip_address}"
}

output "router-02" {
  value = "${sakuracloud_server.router-02-server.ip_address}"
}

output "router-03" {
  value = "${sakuracloud_server.router-03-server.ip_address}"
}

output "host-02" {
  value = "${sakuracloud_server.host-02-server.ip_address}"
}
