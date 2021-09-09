#!/usr/bin/env bash

echo -e "\nInstalling cmake, clang, zstd and software-properties-common"
sudo apt install cmake clang zstd software-properties-common -y


echo -e "\n\nInstalling latest stable wireshark"
sudo add-apt-repository --y ppa:wireshark-dev/stable
sudo apt-get update
sudo apt install wireshark wireshark-dev -y

echo "Done! Run build.sh to build project"
