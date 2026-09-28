Spoof common "trusted" ports — many old firewalls allow anything from port 53/80/443
nmap --source-port 53 -sS <target>
nmap -g 88 <target>