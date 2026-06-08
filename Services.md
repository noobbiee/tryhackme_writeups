<img width="872" height="336" alt="image" src="https://github.com/user-attachments/assets/bbc10b3b-0b31-4a26-9119-af6815ea7305" />

```
nmap -p- -Pn $target -v --min-rate 5000 max-rtt-timeout 1000 --max-retries 5 -oN nmap_ports.txt
```
<img width="500" height="707" alt="image" src="https://github.com/user-attachments/assets/f960c576-f389-4751-a2e4-c866f6a778c4" />

```
nmap -Pn $target -sVC -v -oN nmap_svc.txt
```
<img width="911" height="668" alt="image" src="https://github.com/user-attachments/assets/a8bcb8aa-3980-4d7e-955d-23a67dc50d6f" />

<img width="911" height="668" alt="image" src="https://github.com/user-attachments/assets/2a0661e9-328f-4ec5-a98f-2015067cdbc1" />

```
nmap -T5 -Pn $target -v --script vuln -oN vuln_scan.txt
```
<img width="892" height="597" alt="image" src="https://github.com/user-attachments/assets/6c6ad12b-ac08-4739-89e5-52e4513a48e1" />

<img width="932" height="446" alt="image" src="https://github.com/user-attachments/assets/d03fc78f-7f0e-421b-8556-03b054fad73e" />


Add domain address and ip address to the known hosts 

<img width="600" height="194" alt="image" src="https://github.com/user-attachments/assets/ad98ad54-d22d-482b-affd-016deda04b3e" />

