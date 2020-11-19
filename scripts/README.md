# setup
You can develop on sakura cloud.
* required
    * terraform(0.12.5 <= x)
    * ansible(2.8.3 <= x)
    * terraform-provider-sakuracloud(1.15.2 <= x)
        * hint: [Terraform for さくらのクラウド](https://sacloud.github.io/terraform-provider-sakuracloud/installation/)

## Prepare Create Archive image
```sh
sudo apt update 
sudo apt upgrade -y
sudo apt install -y make
# selected ubuntu image.
git clone https://github.com/usbkey9/uktools && cd uktools
# download version.
make
# select new kernel
sudo uktools-upgrade

sudo apt update 
sudo apt upgrade -y
sudo apt install -y bison flex clang gcc llvm libelf-dev bc libssl-dev tmux trace-cmd pkg-config  libtalloc-dev libpcsclite-dev libmnl-dev autoconf libtool binutils-dev libelf-dev libreadline-dev ethtool

cd ~
wget https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/iproute2-5.5.0.tar.gz
tar -xzvf ./iproute2-5.5.0.tar.gz
cd ./iproute2-5.5.0
sudo make && sudo make install


cd ~
sudo ldconfig -v
git clone git://git.osmocom.org/libgtpnl.git
cd libgtpnl
autoreconf -fi
./configure
make
sudo make install
sudo ldconfig

# bpftools
cd ~
version=$(uname -r)
KERNEL_VERSION="v${version:0:3}"
git clone --branch $KERNEL_VERSION --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
cd linux/tools/bpf
sudo make
sudo cp bpftool/bpftool /usr/local/bin/
```

## Go Setup

select archive image(fix terraform file)

```sh
terraform init
terraform apply
chmod +x inventry_handler.py
ssh-keygen  -f ~/.ssh/toor
ansible-playbook -u ubuntu --private-key=./id_rsa -i inventry_handler.py setup.yml --extra-vars "ansible_sudo_pass=PUT_YOUR_PASSWORD_HERE"
```
