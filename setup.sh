#!/bin/bash
clear
echo -e "\033[1;91m    
░       ░░░        ░░  ░░░░  ░░  ░░  ░░░░░░░░  ░░░░  ░
▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒  ▒▒▒▒▒▒▒▒▒  ▒▒  ▒▒
▓  ▓▓▓▓  ▓▓      ▓▓▓▓▓  ▓▓  ▓▓▓  ▓▓  ▓▓▓▓▓▓▓▓▓▓    ▓▓▓
█  ████  ██  ██████████    ████  ██  █████████  ██  ██
█       ███        █████  █████  ██        ██  ████  █
██████████████████████████████████████████████████████
     \033[1;90m github.com/VritraSecz     ~  \033[1;92m  Version: 1.1.2 "

echo -e "\n\033[1;90m~ All the necessary packages and modules is about to install in your termux"
echo -e "\033[1;94m"
read -p "Press ENTER To Continue"
echo -e "\033[1;92m"
apt update -y
apt upgrade -y
apt install git -y
apt install python -y
apt install python3 -y
apt install wget -y
apt install curl -y
apt install python-pip -y
pip install lolcat
pip install bs4
pip install beautifulsoup4
pip install requests
pip install instaloader
echo -e "\n\033[1;92m~ Installation is done\n~ Now type 'python devilx.py' to run the tool\n"
exit
