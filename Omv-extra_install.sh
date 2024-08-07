#!/bin/bash

# shellcheck disable=SC2086,SC2181

declare -i version

if [[ $(id -u) -ne 0 ]]; then
  echo "This script must be executed as root or using sudo."
  exit 99
fi

arch="$(dpkg --print-architecture)"
echo "Arch :: ${arch}"

# exit if not supported architecture
case ${arch} in
  arm64|armhf|amd64|i386)
    echo "Supported architecture"
    ;;
  *)
    echo "Unsupported architecture :: ${arch}"
    exit 5
    ;;
esac

url="https://github.com/OpenMediaVault-Plugin-Developers/packages/raw/master/"

version=$(dpkg -l openmediavault | awk '$2 == "openmediavault" { print substr($3,1,1) }')
echo "OMV ${version}"

codename="$(lsb_release --codename --short)"
echo "Codename :: ${codename}"

if [ ${version} -lt 5 ]; then
  echo "Unsupported version of openmediavault"
  exit 0
fi

list="/etc/apt/sources.list.d/omvextras.list"
if [ -f "${list}" ]; then
  rm ${list}
fi

echo "Downloading omv-extras.org plugin for openmediavault ${version}.x ..."
file="openmediavault-omvextrasorg_latest_all${version}.deb"

if ! grep -qrE "^deb.*${codename}\s+main" /etc/apt/sources.list*; then
  echo "Adding missing main repo..."
  echo "deb http://deb.debian.org/debian/ ${codename} main contrib non-free" | tee -a /etc/apt/sources.list
fi
if ! grep -qrE "^deb.*${codename}-updates\s+main" /etc/apt/sources.list*; then
  echo "Adding missing main updates repo..."
  echo "deb http://deb.debian.org/debian/ ${codename}-updates main contrib non-free" | tee -a /etc/apt/sources.list
fi

echo "Updating repos before installing..."
apt-get update

echo "Install prerequisites..."
apt-get --yes --no-install-recommends install gnupg
if [ $? -gt 0 ]; then
  echo "Unable to install prerequisites. Exiting."
  exit 10
fi

if [ -f "${file}" ]; then
  rm ${file}
fi
wget ${url}/${file}
if [ -f "${file}" ]; then
  dpkg -i ${file}

  if [ $? -gt 0 ]; then
    echo "Installing other dependencies ..."
    apt-get -f install
  fi

  echo "Updating repos ..."
  apt-get update

  # Remove omv-flashmemory package if it's installed
  if dpkg -l | grep -qw omv-flashmemory; then
    echo "Removing omv-flashmemory package..."
    apt-get remove --purge -y omv-flashmemory
  fi
else
  echo "There was a problem downloading the package."
fi

echo -e "\n\nPress ctrl-shift-R in the browser after signing in to the OMV web interface."

exit 0
