# idevicerestore

*A command-line application to restore firmware files to iOS devices.*

![](https://github.com/libimobiledevice/idevicerestore/actions/workflows/build.yml/badge.svg)

## Table of Contents
- [Features](#features)
- [Building](#building)
  - [Prerequisites](#prerequisites)
    - [Linux (Debian/Ubuntu based)](#linux-debianubuntu-based)
    - [macOS](#macos)
    - [Windows](#windows)
  - [Configuring the source tree](#configuring-the-source-tree)
  - [Building and installation](#building-and-installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [Links](#links)
- [License](#license)
- [Credits](#credits)

## Features

The idevicerestore application is a full reimplementation of all granular steps
which are performed during the restore of a firmware to a device.

In general, upgrades and downgrades are possible, however subject to
availability of SHSH blobs from Apple for signing the firmware files.

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

## Building

### Prerequisites

You need to have a working compiler (gcc/clang) and development environent
available. This project uses autotools for the build process, allowing to
have common build steps across different platforms.
Only the prerequisites differ and they are described in this section.

#### Linux (Debian/Ubuntu based)

* Install all required dependencies and build tools:
  ```shell
  sudo apt-get install \
  	build-essential \
  	pkg-config \
  	checkinstall \
  	git \
  	autoconf \
  	automake \
  	libtool-bin \
  	libreadline-dev \
  	libusb-1.0-0-dev \
  	libplist-dev \
  	libimobiledevice-dev \
  	libimobiledevice-glue-dev \
  	libtatsu-dev \
  	libcurl4-openssl-dev \
  	libssl-dev \
  	libzip-dev \
  	zlib1g-dev
  ```
  NOTE: [libtatsu](https://github.com/libimobiledevice/libtatsu) (and thus `libtatsu-dev`)
  is a new library that was just published recently, you have to
  [build it from source](https://github.com/libimobiledevice/libtatsu?tab=readme-ov-file#building).
  Also, other `*-dev` packages might not be available for your distribution,
  so you will have to build these packages on your own as well.

#### macOS

* Make sure the Xcode command line tools are installed.

  **Option 1**:
  The easiest way to build and install `idevicerestore` for macOS is using
  the following build script which will do the work for you, it will build
  and install all required dependencies:
  ```bash
  mkdir -p limd-build
  cd limd-build
  curl -o ./limd-build-macos.sh -L https://is.gd/limdmacos
  bash ./limd-build-macos.sh
  ```
  Follow the prompts of the script and you should have a working `idevicerestore`
  available.

  **Option 2**:
  Use either [MacPorts](https://www.macports.org/)
  or [Homebrew](https://brew.sh/) to install `automake`, `autoconf`, and `libtool`.

  Using MacPorts:
  ```shell
  sudo port install libtool autoconf automake
  ```

  Using Homebrew:
  ```shell
  brew install libtool autoconf automake
  ```

  `idevicerestore` has a few dependencies from the libimobiledevice project.
  You will have to build and install the following:
  * [libplist](https://github.com/libimobiledevice/libplist)
  * [libimobiledevice-glue](https://github.com/libimobiledevice/libimobiledevice-glue)
  * [libusbmuxd](https://github.com/libimobiledevice/libusbmuxd)
  * [libimobiledevice](https://github.com/libimobiledevice/libimobiledevice)
  * [libirecovery](https://github.com/libimobiledevice/libirecovery)
  * [libtatsu](https://github.com/libimobiledevice/libtatsu)

  Check their `README.md` for building and installation instructions.

#### Windows

* Using [MSYS2](https://www.msys2.org/) is the official way of compiling this project on Windows. Download the MSYS2 installer
  and follow the installation steps.

  It is recommended to use the _MSYS2 MinGW 64-bit_ shell. Run it and make sure the required dependencies are installed:

  ```shell
  pacman -S base-devel \
  	git \
  	mingw-w64-x86_64-gcc \
  	make \
  	libtool \
  	autoconf \
  	automake-wrapper
  ```
  NOTE: You can use a different shell and different compiler according to your needs. Adapt the above command accordingly.

  `idevicerestore` has a few dependencies from the libimobiledevice project.
  You will have to build and install the following:
  * [libplist](https://github.com/libimobiledevice/libplist)
  * [libimobiledevice-glue](https://github.com/libimobiledevice/libimobiledevice-glue)
  * [libusbmuxd](https://github.com/libimobiledevice/libusbmuxd)
  * [libimobiledevice](https://github.com/libimobiledevice/libimobiledevice)
  * [libirecovery](https://github.com/libimobiledevice/libirecovery)
  * [libtatsu](https://github.com/libimobiledevice/libtatsu)

  Check their `README.md` for building and installation instructions.


### Configuring the source tree

You can build the source code from a git checkout, or from a `.tar.bz2` release tarball from [Releases](https://github.com/libimobiledevice/idevicerestore/releases).
Before we can build it, the source tree has to be configured for building. The steps depend on where you got the source from.

* **From git**

  If you haven't done already, clone the actual project repository and change into the directory.
  ```shell
  git clone https://github.com/libimobiledevice/idevicerestore.git
  cd idevicerestore
  ```

  Configure the source tree for building:
  ```shell
  ./autogen.sh
  ```

* **From release tarball (.tar.bz2)**

  When using an official [release tarball](https://github.com/libimobiledevice/idevicerestore/releases) (`idevicerestore-x.y.z.tar.bz2`)
  the procedure is slightly different.

  Extract the tarball:
  ```shell
  tar xjf idevicerestore-x.y.z.tar.bz2
  cd idevicerestore-x.y.z
  ```

  Configure the source tree for building:
  ```shell
  ./configure
  ```

Both `./configure` and `./autogen.sh` (which generates and calls `configure`) accept a few options, for example `--prefix` to allow
building for a different target folder. You can simply pass them like this:

```shell
./autogen.sh --prefix=/usr/local
```
or
```shell
./configure --prefix=/usr/local
```

Once the command is successful, the last few lines of output will look like this:
```
[...]
config.status: creating config.h
config.status: config.h is unchanged
config.status: executing depfiles commands
config.status: executing libtool commands

Configuration for idevicerestore 1.1.0:
-------------------------------------------

  Install prefix: .........: /usr/local

  Now type 'make' to build idevicerestore 1.1.0,
  and then 'make install' for installation.
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
* Commit messages should describe the change well without being too short
* Try to split larger changes into individual commits of a common domain
* Use your real name and a valid email address for your commits

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

README Updated on: 2024-06-19
