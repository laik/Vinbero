# -*- mode: ruby -*-
Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-19.04"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
  end

  config.vm.synced_folder "./scripts", "/root/scripts"
  config.vm.provision "shell", privileged: true, path: "./setup.sh"
end
