# ksmbd-tools

[![Build Status](https://app.travis-ci.com/cifsd-team/ksmbd-tools.svg?branch=master)](https://app.travis-ci.com/cifsd-team/ksmbd-tools)
[![License](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

[ksmbd-tools](https://github.com/cifsd-team/ksmbd-tools)
is a collection of userspace utilities for
[the ksmbd kernel server](https://www.kernel.org/doc/html/latest/filesystems/cifs/ksmbd.html)
merged to mainline in the Linux 5.15 release.

## Table of Contents

- [Building and Installing](#building-and-installing)
- [Example Usage](#example-usage)

## Building and Installing

You should first check if your distribution already packages ksmbd-tools,
and if that is the case, consider installing it from the package manager.
Otherwise, follow these instructions to build it yourself.
Either the GNU Autotools or Meson build system can be used.

Dependencies for Debian and its derivatives:
```
git gcc autoconf automake libtool meson libnl-3-dev libnl-genl-3-dev libglib2.0-dev
```

Dependencies for RHEL, its derivatives, and openSUSE:
```
git gcc autoconf automake libtool meson libnl3-devel glib2-devel
```

Autotools build:
```sh
git clone https://github.com/cifsd-team/ksmbd-tools.git
cd ksmbd-tools
./autogen.sh
./configure
make
sudo make install
```

Meson build:
```sh
git clone https://github.com/cifsd-team/ksmbd-tools.git
cd ksmbd-tools
mkdir build
cd build
meson ..
ninja
sudo ninja install
```

By default, the utilities are in `/usr/local/sbin` and the files they use by
default are under `/usr/local/etc` in the `ksmbd` directory.

If you would like to install ksmbd-tools under `/usr`, where it may conflict
with your distribution's packages, give `--prefix=/usr` and `--sysconfdir=/etc`
as options to `configure` or `meson`. In that case, the utilities are in
`/usr/sbin` and the files they use by default are under `/etc` in the `ksmbd`
directory.

If you have systemd and it meets at least the minimum version required, the
build will install the `ksmbd.service` unit file. The unit file supports the
usual unit commands and handles loading of the kernel module. Note that the
location of the unit file may conflict with ksmbd-tools installed using the
package manager. You can bypass the version check and choose the unit file
directory yourself by giving `--with-systemdsystemunitdir=DIR` and
`-Dsystemdsystemunitdir=DIR` as an option to `configure` or `meson`,
respectively.

## Example Usage

```sh
# if you built and installed ksmbd-tools yourself, by default,
# the utilities are in `/usr/local/sbin',
# the default user database is `/usr/local/etc/ksmbd/ksmbdpwd.db', and
# the default config file is `/usr/local/etc/ksmbd/smb.conf'
#
# otherwise, most likely,
# the utilities are in `/usr/sbin',
# the default user database is `/etc/ksmbd/ksmbdpwd.db', and
# the default config file is `/etc/ksmbd/smb.conf'

# add a share (case insensitive) to the default config file
# `--options' takes a single argument, so quote it accordingly in your shell
# note that the shell expands `$HOME' here, `ksmbd.addshare' will never do it
# newline is the only safe character to use as an option separator
sudo ksmbd.addshare --add-share=MyShare --options="
path = $HOME/MyShare
read only = no
"

# create the share path directory
# the share stores files in this directory using its underlying filesystem
mkdir -vp $HOME/MyShare

# the default config file now looks like this:
#
# [myshare]
#         path = /home/tester/MyShare
#         read only = no
#
# the `[global]' section contains options that are not share specific
# you can set the default options for all shares by adding them to `[global]'
# `ksmbd.addshare` cannot edit `[global]', so do it with a text editor
# see `Documentation/configuration.txt' for more details

# add a user to the default user database
# you will be prompted for a password
sudo ksmbd.adduser --add-user=MyUser

# there is no UNIX user called `MyUser' so it has to be mapped to one
# we can force all users accessing the share to map to a UNIX user and group

# update the options of a share in the default config file
sudo ksmbd.addshare --update-share=MyShare --options="
force user = $USER
force group = $USER
"

# the default config file now looks like this:
#
# [myshare]
#         force user = tester
#         path = /home/tester/MyShare
#         force group = tester
#         read only = no
#

# load the kernel module if it is not already loaded
sudo modprobe ksmbd

# run the user mode and kernel mode daemons
# all interfaces are listened to by default
sudo ksmbd.mountd

# mount the new share with cifs-utils and authenticate as the new user
# you will be prompted for a password
sudo mount -o user=MyUser //127.0.0.1/MyShare /mnt

# you can now access the share at `/mnt'
sudo touch /mnt/hello_from_cifs_utils

# unmount the share
sudo umount /mnt

# update the password of a user in the default user database
# `--password' can be used to give the password instead of prompting
sudo ksmbd.adduser --update-user=MyUser --password=MyNewPassword

# authenticating with the new password will *not* work unless ksmbd is restarted
sudo mount -o user=MyUser,pass=MyNewPassword //127.0.0.1/MyShare /mnt

# delete a user from the default user database
sudo ksmbd.adduser --del-user=MyUser

# authenticating as the deleted user *will* work until ksmbd is restarted
sudo mount -o user=MyUser //127.0.0.1/MyShare /mnt
sudo umount /mnt

# this need to restart when updating and deleting users applies to shares as well
# however, adding new users and shares does *not* require a restart
# restarting ksmbd means you run `ksmbd.mountd' again after you shut it down

# toggle printing of the `all' debug component
sudo ksmbd.control --debug=all

# shutdown the user and kernel mode daemons
sudo ksmbd.control --shutdown

# remove the kernel module
sudo rmmod ksmbd
```
