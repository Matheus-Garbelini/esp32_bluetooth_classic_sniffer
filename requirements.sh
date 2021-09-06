#!/usr/bin/env bash

echo -e "\nInstalling cmake, clang and software-properties-common"
sudo apt install cmake clang software-properties-common -y


echo -e "\n\nInstalling latest stable wireshark"
sudo add-apt-repository --yes ppa:wireshark-dev/stable
sudo apt-get update
sudo apt install wireshark -y

echo "Done! Run build.sh to build project"
