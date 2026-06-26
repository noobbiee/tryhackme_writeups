# Roasted

<img width="556" height="220" alt="image" src="https://github.com/user-attachments/assets/a2a3c0d2-f051-4b45-a9e5-aca1830bd570" />

# open port scan

```
sudo nmap -p- --open -Pn $target -v -T5 --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 -oN openports.txt
```
<img width="692" height="491" alt="image" src="https://github.com/user-attachments/assets/fb0e8e11-748b-4d6b-9fd2-ad3fa03d2120" />

# Service version scan

```
sudo nmap -p 53,88,135,139,389,445,464,593,636 -sCV $target
```
<img width="914" height="484" alt="image" src="https://github.com/user-attachments/assets/01fa437a-3ac6-44e5-991d-77f9874bf9e3" />


# vulnerability scan
```
sudo nmap --script vuln $target
```
<img width="824" height="460" alt="image" src="https://github.com/user-attachments/assets/ba47b752-a2ba-4cc6-a499-4637195110d8" />


Since we have found smb, kerberos it shows the signs of presence of domain. lets check smb

# Anonymous login

```
rpcclient -N $target
```

<img width="689" height="116" alt="image" src="https://github.com/user-attachments/assets/d23a3c71-fb48-4c3d-8c5c-242056dec972" />

# Anonymous listing

```
smbclient -L \\\\$target\\ -N
```
<img width="748" height="252" alt="image" src="https://github.com/user-attachments/assets/858efd9c-6cff-402b-86f2-8674a1ce32a8" />

We have found some shares, lets see if we can access them

```
smbclient -U "" //$target/VulnNet-Business-Anonymous
```
<img width="909" height="375" alt="image" src="https://github.com/user-attachments/assets/ba41af12-6099-4780-830a-8edb9f580d75" />

```
smbclient -U "" //$target/VulnNet-Enterprise-Anonymous
```
<img width="914" height="368" alt="image" src="https://github.com/user-attachments/assets/677ac0fa-b629-4c17-875e-8bb1b139b627" />

We were able to access the share and access some files on both the shares. Since it was text files we could find information
related to the domain, users, or sometimes even credentials.

After going through those files we were able to find some names which we could use to create username to perform kerbrute.

Alexa Whitehat,
Jack Goldenhand,
TryHackMe,
Tony Skid,
Johnny Leet

These are the list of names we found from the files

Lets find the domain name to use kerbrute















