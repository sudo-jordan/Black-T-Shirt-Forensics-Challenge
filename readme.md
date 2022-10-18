# Black T-Shirt Forensics Challenge

## Scenario
Security engineers working for the HiTek Company were running a data loss prevention program. The engineers are suspicious that there has been a potential data exfiltration of sensitive company information. This prompted the creation of two forensic images of two related computers and the network traffic between them. These files were then passed off to the investigation group who were tasked to take over the files and conclude whether there was data exfiltration that occurred or not, within the HiTeK company.

## Tools Used:
- Autopsy v4.19.3
- NetworkMiner v2.7.3
- Wireshark v3.6.3
- Tcpdump v4.99.1
- John The Ripper v1.9.0
- Ophcrack v3.8.0
- Certutil (built-in Windows command)


## Identified Machines & IP Addresses:
- 3 machines and multiple IP’s identified
    - Windows Machine (Computer1.E01)
      - **Hostname:** DESKTOP-A8BOTBH
      - **IPv4:** 192.168.0.6
    - Ubuntu Virtual Machine
        - Found within Windows Machine
    - Linux Server (Computer2.E01)
      - **Hostname:** web-srv-02
      - **IPv4:** 192.168.0.8

## Network Analysis:
- Wireshark was used for the analysis
- FTP connection between Windows machine & Linux server discovered
- Credentials for FTP server found in plaintext:
  - **webmaster:password**
- Linux server sent 2 zip files to Windows machine via FTP
    - BusinessStrategy.zip
    - Secrets.zip
- Directories to files were then deleted on Linux server
- The images below show the FTP server credentials shown through Wireshark & proof of exfiltration:

<details open><summary>FTP Images</summary>

![FTP credentials](https://github.com/sudo-jordan/Black-T-Shirt-Forensics-Challenge/blob/main/img/ftp_credentials.png?raw=true)
![Proof of Exfiltration](../img/ftp_files_found.png)

</details>

## Passwords/Credentials:
- 7 passwords cracked
    - 3 belong to Windows machine
    - 2 to Ubuntu machine
    - 2 to zip files
- 3 passwords found scattered within documents and files
    - These credentials are for a site titled www.crazywickedawesome.com
- Windows passwords stored in `\Windows\System32\config\Sam`
- Used Ophcrack to grab NTLM hashes & cracked them
- Ubuntu machine passwords stored in /etc/shadow as SHA256 hashes
    - Used John the Ripper to crack
- Used custom wordlist to crack zip file passwords (finalword.txt)
    - BusinessStrategy.zip = **crazylongpassword**
    - Secrets.zip = **VeryLongP@ssw0rd**

<details open><summary>Table of Credentials</summary>
<center>

| User Account 	    | Password	    |
|---------------	|:---------:	|
| tester        	| Monkey    	|
| Carlson       	| 12345     	|
| Johnathan     	| letmein   	|
| webmaster     	| password  	|
| cknight       	| popcorn   	|

</center>

<center>

| Usernames  (www.crazywickedawesome.com) 	| Passwords 	| File Name 	| File Path 	|
|:---:	|:---:	|:---:	|:---:	|
| evilhenchman 	| MyP@ssw0rd!@# 	| Next-Character.docx 	| /Users/tester/Documents/Next-Character.docx 	|
| henchmen 	| P@ssw0rd!@# 	| grays.jpg 	| /Users/tester/Documents/grays.jpg 	|
| Laslow 	| FritoLay 	| MMC.exe 	| /Windows/MMC.exe 	|

</center>

</details>

## Contents of ZIP Files:
With both ZIP files being password protected, once cracked there were .RTF files with matching names.
The images below show the contents of **BusinessStrategy.zip** and **Secrets.zip**:

<details open><summary>Images of ZIP Contents</summary>

![BusinessStrategy.zip Contents](img/../../img/zip_contents1.png)
![Secrets.zip](../img/zip_contents2.png)

</details>

## Hashes:

<details open><summary>Master Hash Table</summary>
<center>

|         File Name        	|             MD5 Hash             	|                SHA1 Hash                 	|
|:------------------------:	|:--------------------------------:	|:----------------------------------------:	|
| **Computer1.E01**        	| 53ff8a7c786e36824118ccdf5d13cb01 	| 62badc2b2b27095db51408f46931c51ad289dbb3 	|
| **Computer1.E02**        	| 53ff8a7c786e36824118ccdf5d13cb01 	| 4eb10332a7876e39d8153624d7d365b67ccf6630 	|
| **Computer1.E03**        	| 0b38a0e41c5b65aa320f1d02647800e6 	| b7d9f4d5fab03e30c21a2bb845bb6052c38b480a 	|
| **Computer1.E04**        	| f5297dc535f91666a6dbc34aaca330b0 	| 32d20dfd9218cc03dd6ac2a936aa1d8192613a91 	|
| **Computer1.E05**        	| 73c2a071afec76079f7eb9fa64409332 	| fff112b45673b759d950ff0fa8e240adfbf5cd77 	|
| **Computer1.E06**        	| f729bf6a150e881222cb93178db12d0f 	| 5d1b4c35a28edd43d48ae2c2a290f89a055632c8 	|
| **Computer1.E07**        	| 82359df946afb8a48e3cf0d5f0b1dde6 	| 7493f7b667f2f305452bb3fd874688c6923eda9e 	|
| **Computer1.E08**        	| 1c6b0be65195109c77d18436e2846eeb 	| 85e88b711c089fe8635a68e68438e32bf3790ac3 	|
| **Computer2.E01**        	| 762f3742c81aa0d3017674c2083f1e97 	| 0664c64558b5e2c129509d446123aecde2fa07af 	|
| **network.pcapng**       	| 8754862e479eb1e93eaa72d79e12e84d 	| 03acc1be064b52523755b67fe566f789c1f5ee2c 	|
| **BusinessStrategy.zip** 	| c05fc707175f4e09201ae80d9c774d1f 	| 3c16de12b6ddc828c88a2dbc40ea701ce29e589d 	|
| **Secrets.zip**          	| 1142df97fd45fa8ea57f02cc51b457e9 	| e548d41084ecd6a9e4aec2106a96c807fdb7a8d6 	|
| **SAM**                  	| a51701d7e4f78902e6586d3799dbc178 	| afd67eb7e19decbbd79c2633b0b15fa230563f99 	|
| **SYSTEM**               	| b40c6acd32c1e9a41fc55ede67a4848b 	| bfe729681b373e232aac43b959668bc51c417989 	|
| **SVCHOST.EXE-6A349820** 	| 1bda1eb8239ad2d508e47d968cb6a767 	| 28c989dd84f1ee855282e6a6102128d94ade2373 	|
| **Next-character.docx**  	| 983d234db7a9d3d4e51697c2796031d4 	| 46da9bd2423763cf67b4d1facd77b8645a962e5c 	|

</center>

</details>

## Conclusion:
Exfiltration of sensitive information did indeed occur on the network. It is likely that an individual at the corporation had been abusing their permissions or cracked the weak passwords and extracted the sensitive data to provide to HiTeK’s competition. This could have been prevented by using stronger passwords across the entire corporation and monitoring who has what permissions on the network.
