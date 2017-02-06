#e -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"
VAGRANTFILE_LOCAL = 'Vagrantfile.local'

$script = <<SCRIPT
echo 'yes' | sudo add-apt-repository 'ppa:fkrull/deadsnakes-python2.7'
sudo apt-get update && sudo apt-get install -y python2.7 python-pip python-dev git libssl-dev virtualenvwrapper python-virtualenv python-crypto python-pyasn1 libgmp-dev libmpfr-dev libmpc-dev
sudo pip install vex
SCRIPT

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.provision "shell", inline: $script
  config.vm.box = 'ubuntu/trusty64'

  config.vm.network "public_network"
  config.vm.provider :virtualbox do |vb|
    vb.customize ["modifyvm", :id, "--cpus", "2", "--ioapic", "on", "--memory", "512" ]
  end

  if File.file?(VAGRANTFILE_LOCAL)
    external = File.read VAGRANTFILE_LOCAL
    eval external
  end
end
