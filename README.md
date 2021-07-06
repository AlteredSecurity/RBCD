# RBCD

Script written in python to perform Resource-Based Constrained Delegation (RBCD) attack by leveraging Impacket toolkit.

## Usage

```
usage: rbcd.py [-h] -u USERNAME -p PASSWORD -t COMPUTERNAME -f COMPUTERNAME HOSTNAME

Resource-Based Constrained Delegation Attack: allow an attacker controllable (preferably previously created fake) computer for delegation on a target computer (where the attacker has write
access to properties through LDAP)

Required options:
  HOSTNAME              Hostname/ip or ldap://host:port connection string to connect to the AD

Main options:
  -h, --help            show this help message and exit
  -u USERNAME, --user USERNAME
                        DOMAIN\username for authentication
  -p PASSWORD, --password PASSWORD
                        Password or LM:NTLM hash, will prompt if not specified
  -t COMPUTERNAME       Target computer hostname where the attacker has write access to properties
  -f COMPUTERNAME       (Fake) computer hostname which the attacker can control

Example: ./rbcd.py -host 10.10.10.1 -u domain\\user -p P@ssw0rd@123 -t WEB -f FAKECOMP
```

## Blog

[Abusing Resource-Based Constrained Delegation (RBCD) using Linux](https://www.alteredsecurity.com/post/resource-based-constrained-delegation-rbcd)

## Credit

This is a modified version of the [rbcd-attack](https://github.com/tothi/rbcd-attack) script which was initially developed by [an0n](https://twitter.com/an0n_r0). 