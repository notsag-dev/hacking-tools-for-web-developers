# Hacking tools for web developers

We use cutting-edge web servers, well-known authentication frameworks and robust encryption libraries, all of them open source and up to date. We also issue [Let's encrypt](https://letsencrypt.org/) certificates in order to encrypt our traffic and use cloud private networks with well-thought-out security policies. Not even mention the salted hashes for storing passwords and the user input validations on the front-end and on the back-end as well (of course). We think our applications are rock solid, as secure as they can be. But, are they?

These are five tools you can easily set up and use in order to check the security of your servers and web applications just like a malicious actor would. Note that the examples listed below are executed against a vulnerable-on-purpose [Hack the Box](https://www.hackthebox.eu/) machine.

**Warning:** the examples listed below may be intrusive, so be sure to execute them against a local instance of the application or a test environment.

## Nikto
https://github.com/sullo/nikto

Nikto is a fantastic web scanner that scans web servers/apps for detecting server misconfiguration or vulnerability to attacks such as cross-site scripting or clickjacking, among many others. It is beginner friendly and that's why it is a great option to get started with. Additionally, the solution for some of the vulnerabilities detected by Nikto is as simple as adding a new header to your http responses, which may be a sweet quick-win for your team.

Example:

```
$ nikto -host 10.10.10.14

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.14
+ Target Hostname:    10.10.10.14
+ Target Port:        80
+ Start Time:         2020-09-14 20:55:10 (GMT-4)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/6.0
+ Retrieved microsoftofficewebserver header: 5.0_Pub
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'microsoftofficewebserver' found, with contents: 5.0_Pub
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 1.1.4322
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Retrieved dasl header: <DAV:sql>
+ Retrieved dav header: 1, 2
+ Retrieved ms-author-via header: MS-FP/4.0,DAV
+ Uncommon header 'ms-author-via' found, with contents: MS-FP/4.0,DAV
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.
+ WebDAV enabled (SEARCH LOCK PROPFIND MKCOL PROPPATCH UNLOCK COPY listed as allowed)
+ OSVDB-13431: PROPFIND HTTP verb may show the server's internal IP address: http://10.10.10.14/
+ OSVDB-396: /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.
+ OSVDB-3233: /postinfo.html: Microsoft FrontPage default file found.
+ OSVDB-3233: /_vti_inf.html: FrontPage/SharePoint is installed and reveals its version number (check HTML source for more information).
+ OSVDB-3500: /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1376. http://www.securityfocus.com/bid/2252.
+ OSVDB-67: /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST.
+ /_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
+ 8015 requests: 0 error(s) and 27 item(s) reported on remote host
+ End Time:           2020-09-14 21:18:51 (GMT-4) (1421 seconds)
```

## Nmap
https://github.com/nmap/nmap

I discovered this great tool around 12 years ago, and it was mind-blowing to me that Ubuntu came with it installed out-of-the-box! At that point it was the most popular network scanner around, and it still holds that position today. It has many capabilities such as port scanning, service and OS detection, vulnerabilities analysis, and more.

Example:
```
$ nmap -A 10.10.10.14

Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-15 00:06 EDT
Nmap scan report for 10.10.10.14 (10.10.10.14)
Host is up (0.16s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Server Date: Tue, 15 Sep 2020 04:13:15 GMT
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Server Type: Microsoft-IIS/6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.79 seconds
```

## Searchsploit
https://github.com/offensive-security/exploitdb

Searchsploit is a great tool for finding available exploits for applications and kernels. If a vulnerable version of an application is being executed on your server, it may be possible for a malicious actor to exploit it to gain access to your data or perform other types of attacks. On the other hand, being able to execute these verifications ourselves is a great skill to have to defend from those attacks.

It's worth mentioning that searchsploit works pretty well with nmap as after discovering what services are running on a certain server we can search them by version number on searchsploit to see if there are exploits available.

Example:
```
$ searchsploit iis 6.0

------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                             |  Path
------------------------------------------------------------------------------------------- ---------------------------------
Microsoft IIS 4.0/5.0/6.0 - Internal IP Address/Internal Network Name Disclosure           | windows/remote/21057.txt
Microsoft IIS 5.0/6.0 FTP Server (Windows 2000) - Remote Stack Overflow                    | windows/remote/9541.pl
Microsoft IIS 5.0/6.0 FTP Server - Stack Exhaustion Denial of Service                      | windows/dos/9587.txt
Microsoft IIS 6.0 - '/AUX / '.aspx' Remote Denial of Service                               | windows/dos/3965.pl
Microsoft IIS 6.0 - ASP Stack Overflow Stack Exhaustion (Denial of Service) (MS10-065)     | windows/dos/15167.txt
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                   | windows/remote/41738.py
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (1)                                | windows/remote/8704.txt
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)                                | windows/remote/8806.pl
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (Patch)                            | windows/remote/8754.patch
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (PHP)                              | windows/remote/8765.php
Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities                                   | windows/remote/19033.txt
------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

## Gobuster
https://github.com/OJ/gobuster

Gobuster is a widely-used tool to bruteforce paths of a web application. This is useful for detecting certain interesting files and folders that may lead to information disclosure or, even better, remote code execution. In the example below, the `common.txt` list of paths is used. It that can be found in the [SecLists repository](https://github.com/danielmiessler/SecLists).

Example:
```
$ gobuster dir -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt --url 10.10.10.14
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.14
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/09/15 00:33:16 Starting gobuster
===============================================================
/Images (Status: 301)
/_private (Status: 403)
/_vti_bin (Status: 301)
/_vti_bin/_vti_adm/admin.dll (Status: 200)
/_vti_bin/shtml.dll (Status: 200)
/_vti_cnf (Status: 403)
/_vti_log (Status: 403)
/_vti_pvt (Status: 403)
/_vti_txt (Status: 403)
/_vti_bin/_vti_aut/author.dll (Status: 200)
/aspnet_client (Status: 403)
/images (Status: 301)
===============================================================
2020/09/15 00:34:40 Finished
===============================================================
```

## Burp suite
https://github.com/PortSwigger/

Burp suite is a web proxy with many security auditing capabilities. It is particularly good for bypassing front-end validations by intercepting and modifying requests after the validations are executed, how cool is that?! Use the Foxy Proxy extension on your browser along with Burp to turn interception on and off much faster!

## Bonus 1: Metasploit
https://github.com/rapid7/metasploit-framework

Metasploit is a pentesting framework created by Rapid7. It also has a command line interface called `msfconsole` which is the most common way of using it. The only reason I did not include metasploit in the main list is because it exceeds a bit the limits of this post as it may require a bit more effort to be installed and also it deserves a more detailed explanation.

## Bonus 2: Kali Linux
https://www.kali.org/

Kali Linux is a pentesting Debian-based GNU/Linux distribution that has all the mentioned tools pre-installed and many, many others!

