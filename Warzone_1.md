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
'''

<img width="721" height="637" alt="Screenshot from 2025-09-21 12-24-59" src="https://github.com/user-attachments/assets/1c8d3563-067d-41e4-977c-739764a0c255" />

<img width="721" height="637" alt="Screenshot from 2025-09-21 12-27-00" src="https://github.com/user-attachments/assets/ac9820cb-e32f-4826-be90-043a4546f452" />

Task4: Still in VirusTotal, under Community, what threat group is attributed to this IP address?

<img width="1660" height="874" alt="Screenshot from 2025-09-21 12-34-50" src="https://github.com/user-attachments/assets/e523150a-94aa-4442-9707-5fae56c7b2d0" />

Task 5: What is the malware family?
<img width="1660" height="874" alt="Screenshot from 2025-09-21 12-37-49" src="https://github.com/user-attachments/assets/dc6cbdfb-2393-428b-94a5-ce3afd6add8b" />

TASK 6: Do a search in VirusTotal for the domain from question 4. What was the majority file type listed under Communicating Files?

We need to find the domain for the TA505, we can find it in the virustotal
<img width="1586" height="890" alt="Screenshot from 2025-09-21 12-59-07" src="https://github.com/user-attachments/assets/939073e5-dfcb-4c39-9abf-2039a622e9fc" />

<img width="1586" height="890" alt="Screenshot from 2025-09-21 13-00-46" src="https://github.com/user-attachments/assets/6e7380f6-6186-4dda-bcf0-bb8566a9592c" />

It is the majority 

TASK 7: Inspect the web traffic for the flagged IP address; what is the user-agent in the traffic?

'''
_path == "http" id.orig_h==172.16.1.102 | SELECT user_agent
'''
<img width="979" height="710" alt="Screenshot from 2025-09-21 13-07-47" src="https://github.com/user-attachments/assets/b094db95-8bff-4e3a-916c-2a88c03c248a" />

Task 8 : Retrace the attack; there were multiple IP addresses associated with this attack. What were two other IP addresses? Enter the IP addressed defanged and in numerical order. (format: IPADDR,IPADDR)ss


