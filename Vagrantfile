# -*- mode: ruby -*-
Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-19.04"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
  end

  config.vm.synced_folder ".", "/home/vagrant/workspace"
  config.vm.provision "shell", privileged: true, path: "./env_setup.sh"
end
