<img width="936" height="544" alt="Screenshot from 2025-09-21 11-41-11" src="https://github.com/user-attachments/assets/49131036-8bfc-4cc1-a6a7-630ee4b6465c" /># This is the writeups for Carnage 1 room in tryhackme

<img width="932" height="644" alt="Screenshot from 2025-09-21 12-06-17" src="https://github.com/user-attachments/assets/9a66d115-59fa-40f7-8aea-3633812706fd" />

<img width="932" height="644" alt="Screenshot from 2025-09-21 12-06-26" src="https://github.com/user-attachments/assets/b64f278c-e7f0-423b-974c-33fb36e18015" />

Start the machine and open the zone1.pcap with brim

Task1: 
'''
event_type=="alert" | alert.category == "Malware Command and Control Activity Detected" | SELECT alert.signature
'''
<img width="936" height="544" alt="Screenshot from 2025-09-21 11-41-11" src="https://github.com/user-attachments/assets/080ec81e-f558-41c5-913c-f5967971663f" />

That is the signature that trigerred the alert

Task2;
'''
event_type=="alert" | alert.category == "Malware Command and Control Activity Detected" | SELECT alert.signature, src_ip 
'''

<img width="932" height="644" alt="Screenshot from 2025-09-21 12-22-22" src="https://github.com/user-attachments/assets/63d2bdae-0097-45a9-a6cc-6b98d0b81b8f" />

<img width="721" height="637" alt="Screenshot from 2025-09-21 12-23-50" src="https://github.com/user-attachments/assets/35f0d3da-9dfa-41ac-9ec5-28f8519d642a" />

Task3: What IP address was the destination IP in the alert? Enter your answer in a defanged format. 
'''
event_type=="alert" | alert.category == "Malware Command and Control Activity Detected" | SELECT alert.signature, src_ip, dest_ip
```
<img width="721" height="637" alt="Screenshot from 2025-09-21 12-24-59" src="https://github.com/user-attachments/assets/1c8d3563-067d-41e4-977c-739764a0c255" />
