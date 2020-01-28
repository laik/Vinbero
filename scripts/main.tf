  
terraform {
  required_version = ">= 0.12.5"
}

# ubuntu archive
data sakuracloud_archive "ubuntu-archive" {
  name_selectors = ["ubuntu"]
  tag_selectors  = ["ubuntu", "linux", "v5.5"]
}

# pub key
resource sakuracloud_ssh_key_gen "key"{
  name = "pubkey"

  provisioner "local-exec" {
    command = "echo \"${self.private_key}\" > id_rsa; chmod 0600 id_rsa"
  }

  provisioner "local-exec" {
    when    = "destroy"
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
  source_archive_id = "${data.sakuracloud_archive.ubuntu-archive.id}"
  size              = 100
}
resource sakuracloud_disk "host-02-disk" {
  name              = "host-02"
  source_archive_id = "${data.sakuracloud_archive.ubuntu-archive.id}"
  size              = 100
}
resource sakuracloud_disk "router-01-disk" {
  name              = "router-01"
  source_archive_id = "${data.sakuracloud_archive.ubuntu-archive.id}"
  size              = 100
}
resource sakuracloud_disk "router-02-disk" {
  name              = "router-02"
  source_archive_id = "${data.sakuracloud_archive.ubuntu-archive.id}"
  size              = 100
}
resource sakuracloud_disk "router-03-disk" {
  name              = "router-03"
  source_archive_id = "${data.sakuracloud_archive.ubuntu-archive.id}"
  size              = 100
}

# servers
resource sakuracloud_server "host-01-server" {
  name            = "host-01"
  hostname        = "host-01"
  core            = 4
  memory          = 4
  disks           = ["${sakuracloud_disk.host-01-disk.id}"]
  nic             = "shared"
  additional_nics = ["${sakuracloud_switch.h1-rt1-switch.id}"]
  ssh_key_ids     = ["${sakuracloud_ssh_key_gen.key.id}"]
  password          = "PUT_YOUR_PASSWORD_HERE"
  tags              = ["@nic-double-queue"]
  connection {
    type = "ssh"
    user = "ubuntu"
    host        = "${self.ipaddress}"
    private_key = "${sakuracloud_ssh_key_gen.key.private_key}"
  }
  provisioner "remote-exec" {
    # write password mean for the sake of ansible used
    # todo: must better use cloudinit or packer initialize.
    inline = [
      "echo ${self.password} |sudo -S sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config",
      "sudo systemctl restart sshd.service",
      "echo Success",
      ]
  }
}




resource sakuracloud_server "router-01-server" {
  name            = "router-01"
  hostname        = "router-01"
  core            = 4
  memory          = 4
  disks           = ["${sakuracloud_disk.router-01-disk.id}"]
  nic             = "shared"
  additional_nics = ["${sakuracloud_switch.h1-rt1-switch.id}","${sakuracloud_switch.rt1-rt2-switch.id}"]
  tags              = ["@nic-double-queue"]
  ssh_key_ids     = ["${sakuracloud_ssh_key_gen.key.id}"]
  password          = "PUT_YOUR_PASSWORD_HERE"
  connection {
    type = "ssh"
    user = "ubuntu"
    host        = "${self.ipaddress}"
    private_key = "${sakuracloud_ssh_key_gen.key.private_key}"
  }
  provisioner "remote-exec" {
    inline = [
      "echo ${self.password} |sudo -S sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config",
      "sudo systemctl restart sshd.service",
      "echo Success",
      ]
  }
}

resource sakuracloud_server "router-02-server" {
  name            = "router-02"
  hostname        = "router-02"
  core            = 4
  memory          = 4
  disks           = ["${sakuracloud_disk.router-02-disk.id}"]
  nic             = "shared"
  additional_nics = ["${sakuracloud_switch.rt1-rt2-switch.id}","${sakuracloud_switch.rt2-rt3-switch.id}"]
  tags              = ["@nic-double-queue"]
  ssh_key_ids     = ["${sakuracloud_ssh_key_gen.key.id}"]
  password          = "PUT_YOUR_PASSWORD_HERE"
  connection {
    type = "ssh"
    user = "ubuntu"
    host        = "${self.ipaddress}"
    private_key = "${sakuracloud_ssh_key_gen.key.private_key}"
  }
  provisioner "remote-exec" {
    inline = [
      "echo ${self.password} |sudo -S sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config",
      "sudo systemctl restart sshd.service",
      "echo Success",
      ]
  }
}

resource sakuracloud_server "router-03-server" {
  name            = "router-03"
  hostname        = "router-03"
  core            = 4
  memory          = 4
  disks           = ["${sakuracloud_disk.router-03-disk.id}"]
  nic             = "shared"
  additional_nics = ["${sakuracloud_switch.rt2-rt3-switch.id}","${sakuracloud_switch.rt3-h2-switch.id}"]
  tags              = ["@nic-double-queue"]
  ssh_key_ids     = ["${sakuracloud_ssh_key_gen.key.id}"]
  password          = "PUT_YOUR_PASSWORD_HERE"
  connection {
    type = "ssh"
    user = "ubuntu"
    host        = "${self.ipaddress}"
    private_key = "${sakuracloud_ssh_key_gen.key.private_key}"
  }
  provisioner "remote-exec" {
    inline = [
      "echo ${self.password} |sudo -S sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config",
      "sudo systemctl restart sshd.service",
      "echo Success",
    ]
  }
}
resource sakuracloud_server "host-02-server" {
  name            = "host-02"
  hostname        = "host-02"
  core            = 4
  memory          = 4
  disks           = ["${sakuracloud_disk.host-02-disk.id}"]
  nic             = "shared"
  additional_nics = ["${sakuracloud_switch.rt3-h2-switch.id}"]
  tags              = ["@nic-double-queue"]
  ssh_key_ids     = ["${sakuracloud_ssh_key_gen.key.id}"]
  password          = "PUT_YOUR_PASSWORD_HERE"
  connection {
    type = "ssh"
    user = "ubuntu"
    host        = "${self.ipaddress}"
    private_key = "${sakuracloud_ssh_key_gen.key.private_key}"
  }
  provisioner "remote-exec" {
    inline = [
      "echo ${self.password} |sudo -S sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config",
      "sudo systemctl restart sshd.service",
      "echo Success",
      ]
  }
}

output "host-01"{
  value = "${sakuracloud_server.host-01-server.ipaddress}"
}

output "router-01"{
  value = "${sakuracloud_server.router-01-server.ipaddress}"
}

output "router-02"{
  value = "${sakuracloud_server.router-02-server.ipaddress}"
}

output "router-03"{
  value = "${sakuracloud_server.router-03-server.ipaddress}"
}

output "host-02"{
  value = "${sakuracloud_server.host-02-server.ipaddress}"
}
