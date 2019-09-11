# idevicerestore

## About

The idevicerestore tool allows to restore firmware files to iOS devices.

It is a full reimplementation of all granular steps which are performed during
restore of a firmware to a device.

In general, upgrades and downgrades are possible, however subject to
availability of SHSH blobs from Apple for signing the firmare files.

To restore a device, simply run
```bash
idevicerestore -l
```

This will print a selection of firmware versions that are currently being signed
for the attached device. It will then download and restore the selected firmware.

By default, an update restore is performed, which will preserve the user data
(unless the firmware image does not contain a 'Customer Upgrade Install' variant,
in which case an erase restore will be performed).

**WARNING**

This tool can easily destroy your user data irreversibly. Use with caution and
make sure to backup your data before trying to restore.

**In any case, usage is at your own risk.**

## Requirements

Development Packages of:
* libimobiledevice
* libirecovery
* libusbmuxd
* libplist
* libcurl
* libzip
* openssl

Software:
* usbmuxd
* make
* autoheader
* automake
* autoconf
* libtool
* pkg-config
* gcc or clang

## Installation

To compile run:
```bash
./autogen.sh
make
sudo make install
```

## Who/What/Where?

* Home: https://www.libimobiledevice.org/
* Code: `git clone https://git.libimobiledevice.org/idevicerestore.git`
* Code (Mirror): `git clone https://github.com/libimobiledevice/idevicerestore.git`
* Tickets: https://github.com/libimobiledevice/idevicerestore/issues
* Mailing List: https://lists.libimobiledevice.org/mailman/listinfo/libimobiledevice-devel
* IRC: irc://irc.freenode.net#libimobiledevice

## Credits

Apple, iPhone, iPad, iPod, iPod Touch, and Apple TV are trademarks of Apple Inc.
idevicerestore is an independent software tool and has not been
authorized, sponsored, or otherwise approved by Apple Inc.

README Updated on:
	2019-09-11
