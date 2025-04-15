## CTF Enumeration Tools

### Main scripts
- `./osint.sh -d <domain> [-o <outdir>]` OSINT scripts & tips
- `./enum.sh -i <IP> -o <logdir> [-H <host>] [-p <port>]` enumerate host
- `./enum-user.sh -i <IP> -u <user> -p <password>` enumerate host with valid user creds
- `./enum-network.sh -i <interface>` local network discovery
- `./enum-web.sh -u <url>` enum web site/host

---
### Self-sufficient AND included in main scripts 
- `./enum-host-nmap.sh -i <IPs> -x <xmllogfile>` enum host with nmap
- `./enum-web.sh -u <URL> -o <outdir>` enum web service (nikto, nuclei, cewl, ffuf, ...)
- `./domain-discovery.sh -d <domain>` domain info
- `./enum-dns-internal.sh -d <domain> -i <DNS server IP>` enum DNS

---
### Required configs
- `enum.conf`
