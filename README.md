# ksmbd-tools

[![Build Status](https://app.travis-ci.com/cifsd-team/ksmbd-tools.svg?branch=master)](https://app.travis-ci.com/cifsd-team/ksmbd-tools)
[![License](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

[ksmbd-tools](https://github.com/cifsd-team/ksmbd-tools)
is a collection of userspace utilities for
[the ksmbd kernel server](https://www.kernel.org/doc/html/latest/filesystems/smb/ksmbd.html)  
merged to mainline in the Linux 5.15 release.

## Table of Contents

- [Building and Installing](#building-and-installing)
- [Usage](#usage)
- [SMB user quotas](#smb-user-quotas)
- [Packages](#packages)

## Building and Installing

You should first check if your distribution has a package for ksmbd-tools,  
and if that is the case, consider installing it from the package manager.  
Otherwise, follow these instructions to build it yourself. Either the GNU  
Autotools or Meson build system can be used.

Dependencies for Debian and its derivatives: `git` `gcc` `pkgconf` `autoconf`  
`automake` `libtool` `make` `meson` `ninja-build` `gawk` `libnl-3-dev`  
`libnl-genl-3-dev` `libglib2.0-dev`

Dependencies for RHEL and its derivatives: `git` `gcc` `pkgconf` `autoconf`  
`automake` `libtool` `make` `meson` `ninja-build` `gawk` `libnl3-devel`  
`glib2-devel`

### Kerberos 5 support

Kerberos 5 support is disabled by default. To enable it, install the
development files for your Kerberos implementation and make sure `pkg-config`
can find its `krb5` module. Pass `--enable-krb5` to Autotools `configure` or
`-Dkrb5=enabled` to Meson. For example:

```sh
# Autotools
./configure --enable-krb5 --with-rundir=/run

# Meson, from the build directory
meson -Dkrb5=enabled -Drundir=/run ..
```

Continue with `make` and `make install` for Autotools, or `ninja` and
`ninja install` for Meson. Heimdal's ASN.1 library is detected and linked
automatically when required.

Example build and install:
```sh
git clone https://github.com/cifsd-team/ksmbd-tools.git
cd ksmbd-tools

# autotools build

./autogen.sh
./configure --with-rundir=/run

make
sudo make install

# meson build

mkdir build
cd build
meson -Drundir=/run ..

ninja
sudo ninja install
```

By default, the utilities are in `/usr/local/sbin` and the files they use by  
default are under `/usr/local/etc` in the `ksmbd` directory.

If you would like to install ksmbd-tools under `/usr`, where it may conflict  
with ksmbd-tools installed using the package manager, give `--prefix=/usr`  
and `--sysconfdir=/etc` as options to `configure` or `meson`. In that case,  
the utilities are in `/usr/sbin` and the files they use by default are under  
`/etc` in the `ksmbd` directory.

It is likely that you should give `--with-rundir` or `-Drundir` as an option  
to `configure` or `meson`, respectively. This is due to it being likely that  
your system does not mount a tmpfs filesystem at the directory given by the  
default value. Common choices are `/run`, `/var/run`, or `/tmp`. ksmbd-tools  
uses the directory for per-process modifiable data, namely the `ksmbd.lock`  
file holding the PID of the `ksmbd.mountd` manager process. If your autoconf  
supports it, you may instead choose to give `--runstatedir` to `configure`.

If you have systemd and it meets at least the minimum version required, the  
build will install the `ksmbd.service` unit file. The unit file supports the  
usual unit commands and handles loading of the kernel module. Note that the  
location of the unit file may conflict with ksmbd-tools installed using the  
package manager. You can bypass the version check and choose the unit file  
directory yourself by giving `--with-systemdsystemunitdir=DIR` or  
`-Dsystemdsystemunitdir=DIR` as an option to either `configure` or `meson`,  
respectively.

## Usage

Manual pages:
```sh
man 8 ksmbd.addshare
man 8 ksmbd.adduser
man 8 ksmbd.control
man 8 ksmbd.mountd
man 5 ksmbd.conf
man 5 ksmbdpwd.db
```

Example session:
```sh
# If you built and installed ksmbd-tools yourself using autoconf defaults,
# the utilities are in `/usr/local/sbin',
# the default user database is `/usr/local/etc/ksmbd/ksmbdpwd.db', and
# the default configuration file is `/usr/local/etc/ksmbd/ksmbd.conf'.

# Otherwise it is likely that,
# the utilities are in `/usr/sbin',
# the default user database is `/etc/ksmbd/ksmbdpwd.db', and
# the default configuration file is `/etc/ksmbd/ksmbd.conf'.

# Create the share path directory.
# The share stores files in this directory using its underlying filesystem.
mkdir -vp $HOME/MyShare

# Add a share to the default configuration file.
# Note that `ksmbd.addshare' does not do variable expansion.
# Without `--add', `ksmbd.addshare' will update `MyShare' if it exists.
sudo ksmbd.addshare --add \
                    --option "path = $HOME/MyShare" \
                    --option 'read only = no' \
                    MyShare

# The default configuration file now has a new section for `MyShare'.
#
# [MyShare]
#         ; share parameters
#         path = /home/tester/MyShare
#         read only = no
#
# Each share has its own section with share parameters that apply to it.
# A share parameter given in `[global]' changes its default value.
# `[global]' also has global parameters which are not share specific.

# You can interactively update a share by omitting `--option'.
# Without `--update', `ksmbd.addshare' will add `MyShare' if it does not exist.
sudo ksmbd.addshare --update MyShare

# Add a user to the default user database.
# You will be prompted for a password.
sudo ksmbd.adduser --add MyUser

# There is no system user called `MyUser' so it has to be mapped to one.
# We can force all users accessing the share to map to a system user and group.

# Update share parameters of a share in the default configuration file.
sudo ksmbd.addshare --update \
                    --option "force user = $USER" \
                    --option "force group = $USER" \
                    MyShare

# The default configuration file now has the updated share parameters.
#
# [MyShare]
#         ; share parameters
#         force group = tester
#         force user = tester
#         path = /home/tester/MyShare
#         read only = no
#

# Add the kernel module.
sudo modprobe ksmbd

# Start the user and kernel mode daemons.
# All interfaces are listened to by default.
sudo ksmbd.mountd

# Mount the new share with cifs-utils and authenticate as the new user.
# You will be prompted for the password given previously with `ksmbd.adduser'.
sudo mount -o user=MyUser //127.0.0.1/MyShare /mnt

# You can now access the share at `/mnt'.
sudo touch /mnt/new_file_from_cifs_utils

# Unmount the share.
sudo umount /mnt

# Update the password of a user in the default user database.
# `--password' can be used to give the password instead of prompting.
sudo ksmbd.adduser --update --password MyNewPassword MyUser

# Delete a user from the default user database.
sudo ksmbd.adduser --delete MyUser

# The utilities notify ksmbd.mountd of changes by sending it the SIGHUP signal.
# This can be done manually when changes are made without using the utilities.
sudo ksmbd.control --reload

# Toggle ksmbd debug printing of the `smb' component.
sudo ksmbd.control --debug smb

# Some changes require restarting the user and kernel mode daemons.
# Modifying any global parameter is one example of such a change.
# Restarting means starting `ksmbd.mountd' after shutting the daemons down.

# Shutdown the user and kernel mode daemons.
sudo ksmbd.control --shutdown

# Remove the kernel module.
sudo modprobe -r ksmbd
```

## SMB user quotas

Use kernel and ksmbd-tools builds that both include quota IPC support, then
start `ksmbd.mountd` as described above. The daemon needs permission to
administer quotas and access to the same filesystem paths and mounts as the
kernel server. An older daemon cannot handle these requests.

Authenticated users may query their own quota. Listing all records and
setting limits require an SMB account mapped to Linux UID 0, and updates
also require a writable share. Guest sessions cannot query or set quotas.
The examples use existing Linux users `alice` and `bob`, plus `root` as the
quota administrator. Add their SMB credentials with:

```sh
sudo ksmbd.adduser --add alice
sudo ksmbd.adduser --add bob
sudo ksmbd.adduser --add root
```

### Native user quotas

For filesystems such as ext4 and XFS, enable user quota accounting and
enforcement using the filesystem's local administration tools first. The
kernel needs `CONFIG_QUOTACTL` and the filesystem's quota support.
`ksmbd.mountd` uses `quotactl_fd()`. No extra share parameter is needed.
For example, export an existing directory on a filesystem with user quotas:

```ini
[QuotaHomes]
        path = /srv/quota/homes
        read only = no
        valid users = root alice bob
```

Native quotas account for files owned by each Linux UID on the filesystem.
SMB limits are in bytes. Native soft and hard limits are rounded up to
1024-byte quota blocks. Use `-1` for an unlimited limit. A zero limit is
unsupported because the native API uses zero to disable a limit.

### Btrfs qgroups

Btrfs quota records are mapped to qgroups, which account for subvolumes
rather than Linux file owners. The administrator must arrange for users to
store files in their corresponding subvolumes.

The following example assumes Btrfs is already mounted at `/srv/storage`
and the two user subvolumes do not yet exist:

```sh
sudo btrfs quota enable /srv/storage
sudo mkdir -p /srv/storage/homes
sudo chmod 0755 /srv/storage/homes
sudo btrfs subvolume create /srv/storage/homes/alice
sudo btrfs subvolume create /srv/storage/homes/bob
sudo chown alice /srv/storage/homes/alice
sudo chown bob /srv/storage/homes/bob
sudo chmod 0700 /srv/storage/homes/alice /srv/storage/homes/bob

# Find the Linux UIDs and the Btrfs subvolume IDs.
id -u alice
id -u bob
sudo btrfs subvolume show /srv/storage/homes/alice
sudo btrfs subvolume show /srv/storage/homes/bob

# Wait until accounting is consistent, then inspect the qgroups.
sudo btrfs quota rescan -w /srv/storage
sudo btrfs qgroup show -r --sync /srv/storage
```

See [btrfs-quota(8)](https://btrfs.readthedocs.io/en/stable/btrfs-quota.html)
and [btrfs-qgroup(8)](https://btrfs.readthedocs.io/en/stable/btrfs-qgroup.html)
for quota preparation. Level 0 qgroups are created for subvolumes. Higher
level qgroups and simple quotas can also be used with the mapping.

Add this share to `ksmbd.conf`, replacing `1000`, `1001`, `256`, and `257`
with the UIDs and subvolume IDs reported above:

```ini
[QuotaHomes]
        path = /srv/storage/homes
        read only = no
        valid users = root alice bob
        btrfs quota map = 1000:0/256 1001:0/257
```

Each entry is `UID:LEVEL/ID`. Separate entries with spaces or commas.
Both UIDs and qgroup IDs must be unique within a share's map. The qgroups
must exist on the Btrfs filesystem containing the share root. The daemon
does not create qgroups, enable quotas, or move files. Btrfs quota support
does not require `CONFIG_QUOTA`.

Btrfs reports the mapped qgroup's referenced-space usage and hard limit.
It has no soft limit: always set the SMB soft limit to `-1`. A hard limit
of `-1` removes the referenced-space limit. A zero hard limit blocks further
allocation.
Other qgroup limits, including limits on parent qgroups, still apply.
Deleting quota records through SMB is unsupported. Queries fail while
accounting is inconsistent or a quota rescan is running. Usage comes from
the committed quota tree. Use `btrfs qgroup show --sync` to refresh it.

### Querying and setting limits over SMB

After editing `ksmbd.conf` on a running server, reload it and reconnect
clients so that the new share configuration is used:

```sh
sudo ksmbd.control --reload
```

Install Samba's `smbcquotas` on the client. Replace `server` and the example
UID with your server address and Alice's UID. `S-1-22-1-1000` is the Unix
user SID for UID 1000. Each command prompts for the SMB account password:

```sh
# Query Alice's record as Alice.
smbcquotas //server/QuotaHomes -m SMB3 -U alice -n -u S-1-22-1-1000

# List quota records as the administrator.
smbcquotas //server/QuotaHomes -m SMB3 -U root -n -L

# Set a 1 GiB hard limit with no soft limit. This also works for Btrfs.
smbcquotas //server/QuotaHomes -m SMB3 -U root \
        -S 'UQLIM:S-1-22-1-1000:-1/1073741824'

# Query the resulting limit.
smbcquotas //server/QuotaHomes -m SMB3 -U root -n -u S-1-22-1-1000

# Remove both limits.
smbcquotas //server/QuotaHomes -m SMB3 -U root \
        -S 'UQLIM:S-1-22-1-1000:-1/-1'
```

For native quotas, a soft limit can also be set, for example
`UQLIM:S-1-22-1-1000:536870912/1073741824` for 512 MiB soft and 1 GiB hard
limits. The [smbcquotas(1) manual](https://www.samba.org/samba/docs/current/man-html/smbcquotas.1.html)
describes the command syntax and byte units.

SMB operations support user quota queries and limit updates. Enable quota
accounting locally. Filesystem-wide default limits and `FSQFLAGS` updates
are unsupported. Group and project quotas are not exposed through SMB.

## Packages

The following packaging status tracker is provided by
[the Repology project](https://repology.org)
.

[![Packaging status](https://repology.org/badge/vertical-allrepos/ksmbd-tools.svg)](https://repology.org/project/ksmbd-tools/versions)
