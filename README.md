# idevicerestore

*A command-line application to restore firmware files to iOS devices.*

## Features

The idevicerestore application is a full reimplementation of all granular steps
which are performed during the restore of a firmware to a device.

In general, upgrades and downgrades are possible, however subject to
availability of SHSH blobs from Apple for signing the firmare files.

Some key features are:

- **Restore:** Update firmware on iOS devices
- **Firmware:** Use official IPSW firmware archive file or a directory as source
- **Update:** Allows updating the device by default or erasing all data
- **Download:** On demand download of latest available firmware for a device
- **Cache:** Downloaded firmware files are cached locally
- **Custom Firmware:** Restore custom firmware files *(requires bootrom exploit)*
- **Baseband:** Allows you to skip NOR/Baseband upgrade
- **SHSH:** Fetch TSS records and save them as ".shsh" files
- **DFU:** Put devices in pwned DFU mode *(limera1n devices only)*
- **AP Ticket:** Use custom AP ticket from a file
- **Cross-Platform:** Tested on Linux, macOS, Windows and Android platforms
- **History:** Developed since 2010

**WARNING:** This tool can easily __destroy your user data__ irreversibly.

Use with caution and make sure to backup your data before trying to restore.

**In any case, usage is at your own risk.**

## Installation / Getting started

### Debian / Ubuntu Linux

First install all required dependencies and build tools:
```shell
sudo apt-get install \
	build-essential \
	checkinstall \
	git \
	autoconf \
	automake \
	libtool-bin \
	libreadline-dev \
	libusb-1.0-0-dev \
	libplist-dev \
	libimobiledevice-dev \
	libcurl4-openssl-dev \
	libssl-dev \
	libzip-dev \
	zlib1g-dev
```

Then clone, build and install [libirecovery](https://github.com/libimobiledevice/libirecovery.git) which is not yet packaged:
```shell
git clone https://github.com/libimobiledevice/libirecovery.git
cd libirecovery
./autogen.sh
make
sudo make install
cd ..
```

If the configure processes indicates old or missing libraries, your distribution
might not have yet packaged the latest versions. In that case you will have to
clone [these libraries](https://github.com/libimobiledevice/) separately and repeat the process in order to proceed.

Continue with cloning the actual project repository:
```shell
git clone https://github.com/libimobiledevice/idevicerestore.git
cd idevicerestore
```

Now you can build and install it:
```shell
./autogen.sh
make
sudo make install
```

**Important**

idevicerestore requires a properly installed [usbmuxd](https://github.com/libimobiledevice/usbmuxd.git)
for the restore procedure. Please make sure that it is either running or
configured to be started automatically as soon as a device is detected
in normal and/or restore mode. If properly installed this will be handled
by udev/systemd.

## Usage

The primary scenario is to restore a new firmware to a device.
First of all attach your device to your machine.

Then simply run:
```shell
idevicerestore --latest
```

This will print a selection of firmware versions that are currently being signed
and can be restored to the attached device. It will then attempt to download and
restore the selected firmware.

By default, an update restore is performed which will preserve user data.

Mind that if the firmware file does not contain a 'Customer Upgrade Install'
variant, an erase restore will be performed.

You can force restoring with erasing all data and basically resetting the device
by using:
```shell
idevicerestore --erase --latest
```

Please consult the usage information or manual page for a full documentation of
available command line options:
```shell
idevicerestore --help
man idevicerestore
```

## Contributing

We welcome contributions from anyone and are grateful for every pull request!

If you'd like to contribute, please fork the `master` branch, change, commit and
send a pull request for review. Once approved it can be merged into the main
code base.

If you plan to contribute larger changes or a major refactoring, please create a
ticket first to discuss the idea upfront to ensure less effort for everyone.

Please make sure your contribution adheres to:
* Try to follow the code style of the project
* Commit messages should describe the change well without being to short
* Try to split larger changes into individual commits of a common domain
* Use your real name and a valid email address for your commits

We are still working on the guidelines so bear with us!

## Links

* Homepage: https://libimobiledevice.org/
* Repository: https://git.libimobiledevice.org/idevicerestore.git
* Repository (Mirror): https://github.com/libimobiledevice/idevicerestore.git
* Issue Tracker: https://github.com/libimobiledevice/idevicerestore/issues
* Mailing List: https://lists.libimobiledevice.org/mailman/listinfo/libimobiledevice-devel
* Twitter: https://twitter.com/libimobiledev

## License

This project is licensed under the [GNU Lesser General Public License v3.0](https://www.gnu.org/licenses/lgpl-3.0.en.html),
also included in the repository in the `COPYING` file.

## Credits

Apple, iPhone, iPad, iPod, iPod Touch, Apple TV, Apple Watch, Mac, iOS,
iPadOS, tvOS, watchOS, and macOS are trademarks of Apple Inc.

This project is an independent software application and has not been
authorized, sponsored, or otherwise approved by Apple Inc.

README Updated on: 2020-06-12
