## Description:

LDAP password notification service.  
This script uses ppolicies objects and attributes to notify user through email about:  
- password expiration [ Notification will be sent once per day next checking after --alert_time ] 
- exceeded wrong login attempts  [ Notification will be sent if failed login attempts more --wrong_count ]
- account locked [ Notification will be sent if LDAP account locked due to exeeding pwdMaxFailure ]

## Usage as a docker container

**Building:**  
```
docker build --tag notifier .  
docker run --name notifier -e NOTIFIER_LDAP_HOST='ldap' -e NOTIFIER_LDAP_USER_DN='admin' netflyer/ldap-notifier
```
For kubernetes:
```
kubectl apply -f ks8/
```

**LDAP Configuration:**  

*ldap users attributes:*
- userPassword
- mail

*ldap ppolicy attributes:*
- pwdExpireWarning: specifies the number of seconds before a password is due to expire that expiration warning messages will be sent
- pwdMaxAge: specifies password time to live in seconds.
- pwdMaxFailure: specifies the number of failures login attempts before locking account
- pwdLockoutDuration: specifies time during which the user account will be locked due to failures login defined in previouse attribute

**Environment Notifier attributes example:**

All valiables are pretty clear: VARIABLE_NAME='default_value' [ short clarification ]  
```
NOTIFIER_LDAP_HOST='localhost'
NOTIFIER_LDAP_PORT='389'
NOTIFIER_LDAP_TLS='False' [ Is not implemented, TODO in future ]
NOTIFIER_LDAP_USER_DN='cn=reader,ou=people,dc=example,dc=com' [ Full DN name with at least RO permissions. Requiered]
NOTIFIER_LDAP_PASSWORD="secretreader" [ Required ]
NOTIFIER_LDAP_BASE='ou=people,dc=example,dc=com' [ Base name for user searching]
NOTIFIER_LDAP_FILTER="(objectclass=posixAccount)" [ Filter for user account searching ]
NOTIFIER_LDAP_DN_POLICY='cn=default,ou=pwpolicies,dc=example,dc=com' [ Required ]
NOTIFIER_INTERVAL_CHECK='60'[ in min ]
NOTIFIER_ALERT_TIME='08:00' [ 24h format ]
NOTIFIER_WRONG_COUNT='3' [ integer ] 
NOTIFIER_MAIL_SUBJECT='Example Corporation' [ Any text will be added as begin subject name]
#NOTIFIER_MAIL_BODY='Hard coded for now.' [ You can change that in code directly ]
NOTIFIER_MAIL_FROM='LDAP admin<ldap@example.com>'
NOTIFIER_MAIL_LOGIN='ldap@example.com' [ Required ]
NOTIFIER_MAIL_PASSWORD="secretmail" [ Required ]
NOTIFIER_MAIL_SMTP_SERVER="smtp.example.com" [ Required ]
NOTIFIER_MAIL_SMTP_PORT=465
NOTIFIER_DEBUG='True'
```

## Links to related resources
[LDAP notifier images](https://hub.docker.com/r/netflyer/ldap-notifier)  
[OpenLDAP images](https://hub.docker.com/r/netflyer/openldap)  
[OpenLDAP-GUI images](https://hub.docker.com/r/netflyer/openldap-ui) 

## Standalone usage
This script can be used like a standalone service, you can run that like a system.d service for example

**Requirements:**  
python3 with module python-ldap   

Installation requirements for alpine:  
```
apk add python3 python3-dev gcc linux-headers musl-dev openldap-dev
pip3 install python-ldap
```

Help notifier output: 
```
notifier.py --help
usage: notifier.py [-h] [-lh LDAP_HOST] [-lp LDAP_PORT] [--ldap_tls LDAP_TLS] [--ldap_user LDAP_USER] [--ldap_pass LDAP_PASS] [--ldap_base LDAP_BASE] [--ldap_filter LDAP_FILTER]
                   [--ldap_dn_policy LDAP_DN_POLICY] [--interval_check INTERVAL_CHECK] [--alert_time ALERT_TIME] [--wrong_count WRONG_COUNT] [--mail_subject MAIL_SUBJECT] [--mail_sender MAIL_SENDER]
                   [--mail_pass MAIL_PASS] [--mail_smtp_server MAIL_SMTP_SERVER] [--mail_smtp_port MAIL_SMTP_PORT] [--debug DEBUG]

LDAP user notification about password issues

optional arguments:
  -h, --help            show this help message and exit
  -lh LDAP_HOST, --ldap_host LDAP_HOST
                        LDAP server, env(NOTIFIER_LDAP_HOST), default localhost
  -lp LDAP_PORT, --ldap_port LDAP_PORT
                        LDAP server, env(NOTIFIER_LDAP_PORT), default 389
  --ldap_tls LDAP_TLS   Not implemented yet, env (NOTIFIER_LDAP_TLS), default False
  --ldap_user LDAP_USER
                        LDAP account DN, env(NOTIFIER_LDAP_USER_DN). Required!!!
  --ldap_pass LDAP_PASS
                        LDAP account password, env(NOTIFIER_LDAP_PASSWORD). Required!!!
  --ldap_base LDAP_BASE
                        LDAP base DN for search, env(NOTIFIER_LDAP_BASE). Required!!!
  --ldap_filter LDAP_FILTER
                        LDAP filter for search, env(NOTIFIER_LDAP_FILTER), default (objectclass=posixAccount)
  --ldap_dn_policy LDAP_DN_POLICY
                        LDAP ppolicy DN, env(NOTIFIER_LDAP_DN_POLICY). Required!!!
  --interval_check INTERVAL_CHECK
                        Checking interval in minutes, env(NOTIFIER_INTERVAL_CHECK), default 60 min
  --alert_time ALERT_TIME
                        Preferred time to send alerts in 24hours format (HH:MM) e.g. 14:00, env(NOTIFIER_ALERT_TIME), default 08:00
  --wrong_count WRONG_COUNT
                        how many wrong password attempts for notification, env(NOTIFIER_WRONG_COUNT). default 3
  --mail_subject MAIL_SUBJECT
                        Subject email, env(NOTIFIER_MAIL_SUBJECT)
  --mail_from MAIL_FROM
                        Will be insert to field From, env(NOTIFIER_MAIL_FROM), default = mail_login
  --mail_login MAIL_LOGIN
                        Account for email sending, env(NOTIFIER_MAIL_LOGIN). Required!!!
  --mail_pass MAIL_PASS
                        Password for email sending, env(NOTIFIER_MAIL_PASSWORD). Required!!!
  --mail_smtp_server MAIL_SMTP_SERVER
                        SMTP server, env(NOTIFIER_MAIL_SMTP_SERVER). Required!!!
  --mail_smtp_port MAIL_SMTP_PORT
                        SMTP port, env(NOTIFIER_MAIL_SMTP_PORT), default 25
  --debug DEBUG         Debug information to stdout
  ```

P.S. Dear grateful user, if you find any bugs or issues, please let me know about that.  
You can use or modification any part of these codes like you want.
