# Purple-Team-Exercise-on-Wordpress-Site

### Network Topology

 TODO: insert img

### Exposed Services
  Nmap scan results revealed services and OS details.
 
TODO: insert img





### Critical Vulnerabilities

#### Open SSH 
[https://attack.mitre.org/techniques/T1133/]
-Open SSH is an exposed external remote service. Used to provide access to network resources from external locations.
-Can be used by an attacker to gain entry to a system and for persistent access.

#### Misconfigured IAM
[https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication]
-Confirming a user’s identity is critical to security operations. Broken Authentication is a widespread problem rooted in the design of Identity and Access Controls.
-Weak passwords, no failed login attempt lockout, and failure to implement least-privilege provide vectors for an attacker. Here brute force, password guessing, and privilege escalation through sudo were all used.

#### Sensitive Data Exposure
[https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure]
[https://attack.mitre.org/techniques/T1589/]
-An attacker may search for insecure sensitive data. Insecure credentials can allow an attacker to more easily gain access.
-Attackers are able to enumerate users through Wordpress. Additionally, the password for the MySQL database is store plaintext in wp-config.php. Failure can compromise all data on the system.


## Network Hardening Suggestions

### Hardening SSH
 
1.Block all SSH access on port 22 if not necessary for employees
  -Use firewalld to restrict access to SSH on the server to only the internal subnet

2.Network Segmentation
  -Deny direct remote access to into internal systems through use of network proxies, gateways, and firewalls

3.Key Authentication
  -Using Passwordless Authentication prevents unauthorized entry by hacking passwords, while allowing authorized users to set up SSH key connection
  -COMMAND to modify SSH configuration file: sudo vim /etc/ssh/sshd_config

### Hardening Against Password Attacks

1.Secure Password Policy
  -Protects from password guessing and crypto attacks on hashes
  -enforcing password length and complexity policies
  -checking for weak-passwords against password lists
  -password expires after 60 days
  -6 discrete passwords must be used before reuse

2.Account Lockout Threshold
  -Prevents brute force attacks
  -30-minute lockout after 3 failed attempts within 15-minutes
  -alert on failed authentication

### Hardening Against User Enumeration in WordPress

1.Install Wordpress Plugin to stop user enumeration
  -Toggle stop user enumeration in the security fixers tab

2.Fuzzing the parameter author in WordPress home URL
  -User names are vulnerable when usernames are easily identifiable in WPScan
  -Appending an integer onto author names will make names more difficult to identify

### Hardening Against Privilege Escalation with Python script

1. Remove Steven’s sudo permission to python
 
2.Create user groups with least permission
  -Devs, for Michael and Steven
  -makes administration easier

3. Schedule regular IAM audits




