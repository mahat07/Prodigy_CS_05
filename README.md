Prerequisites:
Install npcap:
Download and install npcap from the official website: https://nmap.org/npcap/
During installation, ensure you check the option "Install Npcap in WinPcap API-compatible Mode".
Verify the installation:
After installation, verify that npcap is working correctly. Open a command prompt and run npcap commands such as npcap -v to check the version and ensure it is installed correctly.
Update your Python script to use the correct interface name:
Sometimes the interface name might not be correctly recognized as 'Wi-Fi'. You can use the scapy library to list all available interfaces and choose the correct one.

Running the Script:
Open PowerShell or Command Prompt.
Navigate to Script Directory.
Run the Script with the appropriate interface and optional filter
python packet_sniffer.py Wi-Fi -f "port 80"
