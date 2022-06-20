# ksmbd-tools

### Building

##### Install prerequisite packages:

- For Ubuntu:
  - `sudo apt-get install autoconf libtool pkg-config libnl-3-dev libnl-genl-3-dev libglib2.0-dev`

- For Fedora, RHEL:
  - `sudo yum install autoconf automake libtool glib2-devel libnl3-devel`

- For CentOS:
  - `sudo yum install glib2-devel libnl3-devel`

- For openSUSE:
  - `sudo zypper install glib2-devel libnl3-devel`

##### Building:

- clone this repository
- `cd ksmbd-tools`
- `./autogen.sh`
- `./configure`
- `make`
- `make install`


### Usage

All administration tasks must be done as root.

##### Setup:

- Install ksmbd kernel driver
	- `modprobe ksmbd`
- Create user/password for SMB share
	- `mkdir -p /usr/local/etc/ksmbd`
	- `ksmbd.adduser -a <username>`
	- Enter password for SMB share access
- Create `/usr/local/etc/ksmbd/smb.conf` file
	- Refer `smb.conf.example`
- Add share to `smb.conf`
	- This can be done manually or with `ksmbd.addshare`, e.g.:
	- `ksmbd.addshare -a myshare -o "guest ok = yes, writable = yes, path = /mnt/data"`

	- Note: share options (-o) must always be enclosed with double quotes ("...").
- Start ksmbd user space daemon
	- `ksmbd.mountd`
- Access share from Windows or Linux using CIFS


##### Stopping and restarting the daemon:

First, kill user and kernel space daemon
  - `ksmbd.control -s`

Then, to restart the daemon, run:
  - `ksmbd.mountd`

Or to shut it down completely:
  - `rmmod ksmbd`


### Debugging

- Enable all component prints
  - `ksmbd.control -d "all"`
- Enable a single component (see below)
  - `ksmbd.control -d "smb"`
- Run the command with the same component name again to disable it

Currently available debug components:
smb, auth, vfs, oplock, ipc, conn, rdma


### More...

- ksmbd.adduser
  - Adds (-a), updates (-u), or deletes (-d) a user from user database.
  - Default database file is `/usr/local/etc/ksmbd/users.db`

- ksmbd.addshare
  - Adds (-a), updates (-u), or deletes (-d) a net share from config file.
  - Default config file is `/usr/local/etc/ksmbd/smb.conf`

`ksmbd.addshare` does not modify `[global]` section in config file; only net
share configs are supported at the moment.
