---
title: "[HTB CTF University 2024] - Apolo"
date: 2024-12-19T02:16:44.843Z
lastmod: 2024-12-19T02:16:44.843Z
draft: false
image: banner.png
description: Hack The Box University CTF - Apolo Writeup
categories:
 - Fullpwn
---

## Fullpwn - Apolo

> In the lawless expanse of the Frontier Cluster, Apolo serves as a beacon of security, working to safeguard the Frontier Cluster’s assets from bounty hunters.


## User

### Enumeration

port scan showing two active port, 22 and 80.

Using curl, i managed to obtain server name, which is `apolo.htb`.

![](image.png)

### Web Application

i add the domain name into `/etc/hosts` and starting to enumerate the web pages
![](image-1.png)

In one of the link, i found a subdomain `ai.apolo.htb`
![](image-2.png)

#### FlowiseAI Exploit

I add the subdomain into `/etc/hosts` and starting to access the site. It seems like it use `FlowiseAI`.
![](image-3.png)

It seems that `FlowiseAI` have [authentication bypass vulnerability](https://www.exploit-db.com/exploits/52001).

using the technique mentioned on the exploitdb, i managed to bypsas authentication and obtain credentials id.

![](image-4.png)

```json
[
  {
    "id": "6cfda83a-b055-4fd8-a040-57e5f1dae2eb",
    "name": "MongoDB",
    "credentialName": "mongoDBUrlApi",
    "createdDate": "2024-11-14T09:02:56.000Z",
    "updatedDate": "2024-11-14T09:02:56.000Z"
  }
]
```

The id can be used to read the value of mongodb creds.
![](image-5.png)

```json
{
  "id": "6cfda83a-b055-4fd8-a040-57e5f1dae2eb",
  "name": "MongoDB",
  "credentialName": "mongoDBUrlApi",
  "createdDate": "2024-11-14T09:02:56.000Z",
  "updatedDate": "2024-11-14T09:02:56.000Z",
  "plainDataObj": {
    "mongoDBConnectUrl": "mongodb+srv://lewis:C0mpl3xi3Ty!_W1n3@cluster0.mongodb.net/myDatabase?retryWrites=true&w=majority"
  }
}
```

There's pair of credentials there, which is `lewis:C0mpl3xi3Ty!_W1n3`.

The credentials can be used to logged in using ssh.

![](image-6.png)

Flag: HTB{llm_ex9l01t_4_RC3}

## Root

Our current user have permission to run `rclone` as root using sudo.

![](image-7.png)

Unfortunately, `rclone` is not listed in GTFOBins site
![](image-10.png)

Then i try to check for it's docouomentation, and found that it have `cat` options that can be used to read files.
![](image-8.png)

I can easily read root flag using following command.
![](image-9.png)

Flag: HTB{cl0n3_rc3_f1l3}