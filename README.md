# P4-based Programmable Switches

Building an in-network, load balanced key/value store using a set of P4-based programmable switches.

## P4 Tutorial

1. Install vmware fusion 13 on your macbook (for Apple silicon). Follow this [link](https://customerconnect.vmware.com/en/evalcenter?p=fusion-player-personal-13).
   Please remember to apply for the free personal usage license, otherwise it will be a 7 day trial!

2. Download ubuntu 20.04 ARM Desktop image follow this [link](https://cdimage.ubuntu.com/focal/daily-live/current/focal-desktop-arm64.iso).

3. Port the vm into vmware fusion. This step is straight forward, just follow the prompt instructions.

4. Start the vm and go through the initialization phase. Set the user name and password as `vagrant`. Keep everything else as default.

5. Open a terminal, run `cd ~/Desktop`, then run `sudo apt-get install git vim`

6. Run `git clone https://github.com/824728350/tutorials.git`

7. Run `cd tutorials/vm-ubuntu-20.04; mkdir /home/vagrant/patches`

8. Run `cp patches/mininet-dont-install-python2-2022-apr.patch /home/vagrant/patches/mininet-dont-install-python2-2022-apr.patch`

9. Run `sudo sh root-release-bootstrap.sh`

10. Run `sudo sh root-common-bootstrap.sh`

11. Run `sh user-common-bootstrap.sh` This will reboot the vm.

12. log into the newly created `p4` account, the password is also `p4`. Now you should have a working environoment.
