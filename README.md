# libmspdb

[![Discord](https://dcbadge.limes.pink/api/server/https://discord.gg/YSdGvAhSmH?style=flat)](https://discord.gg/YSdGvAhSmH)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/IntroVirt/libmspdb?color=brightgreen)](https://github.com/IntroVirt/libmspdb/releases/latest)
[![CI Tests](https://github.com/IntroVirt/libmspdb/actions/workflows/ci.yml/badge.svg)](https://github.com/IntroVirt/libmspdb/actions/workflows/ci.yml)
[![Create Release](https://github.com/IntroVirt/libmspdb/actions/workflows/release.yml/badge.svg)](https://github.com/IntroVirt/libmspdb/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Description

**libmspdb** is a parsing library for Microsoft Program Database (PDB) files. This library is primarily used by [IntroVirt](https://github.com/IntroVirt/IntroVirt) to parse memory in Windows virtual machines.

## Quick Start

### Install the latest release

Pre-built debian packages can be downloaded and installed from the latest [release](https://github.com/IntroVirt/libmspdb/releases/latest). For example, with:

```bash
mkdir libmspdb_pkg && cd libmspdb_pkg
wget https://github.com/IntroVirt/libmspdb/releases/latest/download/libmspdb_ubuntu-$(lsb_release -sr)_Release.zip
unzip libmspdb_ubuntu-$(lsb_release -sr)_Release.zip
sudo apt install ./libmspdb_ubuntu-$(lsb_release -sr)_Release/*.deb
```

## Build and install from source

To build from source:

```bash
sudo apt-get install -y cmake libcurl4-openssl-dev libboost-dev git
git clone https://github.com/IntroVirt/libmspdb.git
cd libmspdb/build/
cmake ..
make -j$(nproc)
```

Debian packages can then be built and installed (recommended):

```bash
make package
sudo apt install ./*.deb
```

Or `make` can be used directly to install:

```bash
sudo make install
```

## Interested In Working For AIS?

Check out our [Can You Hack It?®](https://www.canyouhackit.com) challenge and test your skills! Submit your score to show us what you’ve got. We have offices across the country and offer competitive pay and outstanding benefits. Join a team that is not only committed to the future of cyberspace, but to our employee’s success as well.

<p align="center">
  <a href="https://www.ainfosec.com/">
    <img src="https://github.com/IntroVirt/IntroVirt/raw/main/.github/images/ais.png" alt="ais" height="100" />
  </a>
</p>
