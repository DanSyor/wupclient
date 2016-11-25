# coding: utf-8
import os
import re

ipconfigfile = "ip.txt"
ip_re = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$")

def askForIp(configFileTested):
    ip = ""
    if not configFileTested and os.path.exists(ipconfigfile):
        with open(ipconfigfile,'r') as ipconfig:
            ip = ipconfig.read()
    ip_conf = ip
    while not ip_re.match(ip):
        ip = raw_input("Please input the IP address of your Wii U within your local network: ")
    return ip, ip_conf

def confirmIP(ip):
    confirm_select = "random"
    while not confirm_select in ["","y","yes","n","no"]:
        confirm_select = raw_input("Do you confirm "+ip+" is the IP address of your Wii U within your local network? [Y/n] ").lower()
    return confirm_select in ["","y","yes"]

def asknconfirmIP():
    confirmed = False
    configFileTested = False
    while not confirmed:
        ip,ip_conf = askForIp(configFileTested)
        configFileTested = True
        confirmed = confirmIP(ip)
    if ip != ip_conf:
        with open(ipconfigfile,'w') as ipconfig:
            ipconfig.write(ip)
    return ip

# ip = asknconfirmIP()

# print("So let's try to connect to your Wii U with "+ip+ "!")