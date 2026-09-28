nmap -T0 <target>            # paranoid — one probe every 5 min
nmap -T1 <target>            # sneaky
nmap --scan-delay 10s <target>
nmap --max-rate 1 <target>   # 1 packet/sec cap