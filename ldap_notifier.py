#!/usr/bin/python3

from datetime import datetime,date,timedelta
import time
import argparse
from os import environ
import ldap

import email, smtplib, ssl
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

DOCUMENTATION = '''
    Author: Alexey Demidov

    Required: python-ldap
    Installation for alpine:
        apk add python3 python3-dev gcc linux-headers musl-dev openldap-dev
        pip3 install python-ldap

    !!!Please pay attention, script uses only external smtp server!!!

    This script connect to LDAP and notifies user about following:
        - password expiration (Notification is sent once per day at time --alert_time, since ppolicy parameter pwdExpireWarning)
        - exceeded wrong login attempts
        - account locked
    
    To put start parameters you can use environment variables or command line arguments.
    If set up both, the only command line argument will be used.
    For more information please run scripts with --help or -h argument

    Example to put connection parameters from environment variables
        export NOTIFIER_LDAP_HOST='localhost'
        export NOTIFIER_LDAP_PORT='389'
        export NOTIFIER_LDAP_TLS='False'
        export NOTIFIER_LDAP_USER_DN='cn=reader,ou=people,dc=example,dc=com'
        export NOTIFIER_LDAP_PASSWORD="secretpassword"
        export NOTIFIER_LDAP_BASE='ou=people,dc=example,dc=com'
        export NOTIFIER_LDAP_DN_POLICY='cn=default,ou=pwpolicies,dc=example,dc=com'
        export NOTIFIER_INTERVAL_CHECK='60'
        export NOTIFIER_ALERT_TIME='13:00'
        export NOTIFIER_WRONG_COUNT='3'
        export NOTIFIER_MAIL_SUBJECT='Example LTD'
        #export NOTIFIER_MAIL_BODY='Hard coded for now.' You can change that in code
        export NOTIFIER_MAIL_LOGIN='ldap@mail.com'
        export NOTIFIER_MAIL_PASSWORD="ldapmailpassword"
        export NOTIFIER_MAIL_SMTP_SERVER="smtp.mail.com"
        export NOTIFIER_MAIL_SMTP_PORT=25
        export NOTIFIER_DEBUG='True'
    '''
def debug(msg):
    if debug_status: print (msg)

def parse_args():
#Arguments parsing
    ldap_host = environ['NOTIFIER_LDAP_HOST'] if environ.get('NOTIFIER_LDAP_HOST') else 'localhost'
    ldap_port = environ['NOTIFIER_LDAP_PORT'] if environ.get('NOTIFIER_LDAP_PORT') else '389'
    ldap_tls = eval(environ['NOTIFIER_LDAP_TLS']) if environ.get('NOTIFIER_LDAP_TLS') else False
    ldap_user = environ['NOTIFIER_LDAP_USER_DN'] if environ.get('NOTIFIER_LDAP_USER_DN') else False
    ldap_pass = environ['NOTIFIER_LDAP_PASSWORD'] if environ.get('NOTIFIER_LDAP_PASSWORD') else False
    ldap_base = environ['NOTIFIER_LDAP_BASE'] if environ.get('NOTIFIER_LDAP_BASE') else False
    ldap_filter = environ['NOTIFIER_LDAP_FILTER'] if environ.get('NOTIFIER_LDAP_FILTER') else "(objectclass=posixAccount)"
    ldap_dn_policy = environ['NOTIFIER_LDAP_DN_POLICY'] if environ.get('NOTIFIER_LDAP_DN_POLICY') else False
    interval_check = environ['NOTIFIER_INTERVAL_CHECK'] if environ.get('NOTIFIER_INTERVAL_CHECK') else 60
    alert_time = environ['NOTIFIER_ALERT_TIME'] if environ.get('NOTIFIER_ALERT_TIME') else '08:00'
    wrong_count = environ['NOTIFIER_WRONG_COUNT'] if environ.get('NOTIFIER_WRONG_COUNT') else 3
    mail_subject = environ['NOTIFIER_MAIL_SUBJECT'] if environ.get('NOTIFIER_MAIL_SUBJECT') else 'Alert'
    mail_login = environ['NOTIFIER_MAIL_LOGIN'] if environ.get('NOTIFIER_MAIL_LOGIN') else False
    mail_from = environ['NOTIFIER_MAIL_FROM'] if environ.get('NOTIFIER_MAIL_FROM') else mail_login
    mail_pass = environ['NOTIFIER_MAIL_PASSWORD'] if environ.get('NOTIFIER_MAIL_PASSWORD') else False
    mail_smtp_server = environ['NOTIFIER_MAIL_SMTP_SERVER'] if environ.get('NOTIFIER_MAIL_SMTP_SERVER') else False
    mail_smtp_port = environ['NOTIFIER_MAIL_SMTP_PORT'] if environ.get('NOTIFIER_MAIL_SMTP_PORT') else '25'
    debug = eval(environ['NOTIFIER_DEBUG']) if environ.get('NOTIFIER_DEBUG') else False

    parser = argparse.ArgumentParser(description='LDAP user notification about password issues')
    parser.add_argument('-lh','--ldap_host', type=str, default = ldap_host, help='LDAP server, env(NOTIFIER_LDAP_HOST), default localhost')
    parser.add_argument('-lp','--ldap_port', type=str, default = ldap_port, help='LDAP server, env(NOTIFIER_LDAP_PORT), default 389')
    parser.add_argument('--ldap_tls', type=bool, default = ldap_tls, help='Not implemented yet, env (NOTIFIER_LDAP_TLS), default False')
    parser.add_argument('--ldap_user', default = ldap_user, help="LDAP account DN, env(NOTIFIER_LDAP_USER_DN). Required!!!" )
    parser.add_argument('--ldap_pass', default = ldap_pass, help="LDAP account password, env(NOTIFIER_LDAP_PASSWORD). Required!!!" )
    parser.add_argument('--ldap_base', default = ldap_base, help="LDAP base DN for search, env(NOTIFIER_LDAP_BASE). Required!!!" )
    parser.add_argument('--ldap_filter', default = ldap_filter, help="LDAP filter for search, env(NOTIFIER_LDAP_FILTER), default (objectclass=posixAccount)" )
    parser.add_argument('--ldap_dn_policy', default = ldap_dn_policy, help="LDAP ppolicy DN, env(NOTIFIER_LDAP_DN_POLICY). Required!!!" )
    parser.add_argument('--interval_check', type=int, default = interval_check, help="Checking interval in minutes, env(NOTIFIER_INTERVAL_CHECK), default 60 min" )
    parser.add_argument('--alert_time', default = alert_time, help='Preferred time to send alerts in 24hours format (HH:MM) e.g. 14:00, env(NOTIFIER_ALERT_TIME), default 08:00')
    parser.add_argument('--wrong_count', type=int, default = wrong_count, help='how many wrong password attempts for notification, env(NOTIFIER_WRONG_COUNT). default 3')
    parser.add_argument('--mail_subject', default = mail_subject, help='Subject email, env(NOTIFIER_MAIL_SUBJECT)')
    parser.add_argument('--mail_from', default = mail_from, help='Will be insert to field From, env(NOTIFIER_MAIL_FROM), default = mail_login')
    parser.add_argument('--mail_login', default = mail_login, help='Account for email sending, env(NOTIFIER_MAIL_LOGIN). Required!!!')
    parser.add_argument('--mail_pass', default = mail_pass, help='Password for email sending, env(NOTIFIER_MAIL_PASSWORD). Required!!!')
    parser.add_argument('--mail_smtp_server', default = mail_smtp_server, help='SMTP server, env(NOTIFIER_MAIL_SMTP_SERVER). Required!!!')
    parser.add_argument('--mail_smtp_port', default = mail_smtp_port, help='SMTP port, env(NOTIFIER_MAIL_SMTP_PORT), default 25')
    parser.add_argument('--debug', type=bool, required=False, default = debug, help='Debug information to stdout')
    args = parser.parse_args()

    # Check that necessary arguments is setted up
    required = {"ldap_user":args.ldap_user, "ldap_pass":args.ldap_pass, "ldap_base":args.ldap_base, "ldap_dn_policy":args.ldap_dn_policy, "mail_login":args.mail_login, "mail_pass":args.mail_pass, "mail_smtp_server":args.mail_smtp_server}
    for key in required:
        if not required[key]:
            print ("Necessary argument "+key+" is missing, please run application with argument --help")
            exit (1)
    try:
        args.alert_time = datetime.now().replace(hour=int(args.alert_time.split(":")[0]),minute=int(args.alert_time.split(":")[1]),second=0,microsecond=0)
    except:
        print ("Error in alert_time format, please put that's like HH:MM, e.g. 15:00")
        exit (1)

    try:
        args.interval_check=timedelta(minutes=args.interval_check)
    except:
        print ("Error in interval_check please put that like (int) in minutes, e.g. 60")
        exit (1)
    return args

def email_send(sender_email,from_email,sender_pass,receiver_email,subject,email_body,smtp_server,smtp_port):
    message = MIMEMultipart()
    message["From"] = from_email
    message["To"] = receiver_email
    message["Subject"] = subject
    message["Bcc"] = receiver_email  # Recommended for mass emails

    message.attach(MIMEText(email_body, "plain"))
    text = message.as_string()
    # Log in to server using secure context and send email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
        try:
            server.login(sender_email, sender_pass)
            server.sendmail(sender_email, receiver_email.split(','), text)
        except Exception as e:
            print (e)

def check_locked(object,interval):  # Logic: if found pwdAccountLockedTime durung last checking interval, then return True
    debug("Check locked: "+object[0])
    if 'pwdAccountLockedTime' in object[1]:
        #get locked time from object
        locked_time = datetime.strptime(object[1]["pwdAccountLockedTime"][0].decode("utf-8"),'%Y%m%d%H%M%SZ'); debug ("Locked time: "+str(locked_time) )
        if locked_time >= datetime.now()-interval: return True
    return False

def check_expiration(object,pwd_max_age,pwd_expiring_warn):
    debug("Check expiration: "+object[0])
    if "pwdChangedTime" in object[1]: passwd_time = datetime.strptime(object[1]["pwdChangedTime"][0].decode("utf-8"),'%Y%m%d%H%M%SZ')
    else: passwd_time = datetime.strptime(object[1]["createTimestamp"][0].decode("utf-8"),'%Y%m%d%H%M%SZ')
    if (datetime.now()-passwd_time) >= pwd_max_age-pwd_expiring_warn:
        return (datetime.now()-passwd_time)
    return False

def check_failed_login(object,wrong_count,interval): 
    debug("Check failed login: "+object[0])
    if "pwdFailureTime" in object[1]:
        if len(object[1]["pwdFailureTime"]) >= wrong_count and (datetime.strptime(object[1]["pwdFailureTime"][-1].decode("utf-8"),'%Y%m%d%H%M%S.%fZ')) > (datetime.now()-interval): return len(object[1]["pwdFailureTime"])
    return False

def main():
# Taking arguments:
    args = parse_args()
    global debug_status
    debug_status = args.debug
    debug ("Running:"); debug (str(datetime.now()))
    debug ("Arguments:"); debug (args)
    email_body = """This is an email about LDAP password on BellOne Platform"""
    

# Connect to LDAP
    con = ldap.initialize('ldap://'+args.ldap_host+':'+args.ldap_port, bytes_mode=False)
    try:
        con.simple_bind_s(args.ldap_user, args.ldap_pass)
    except Exception as e:
        print (e) ; exit (2)
        
# Start Loop
    while True:
        print ("Checking time: "+str(datetime.now()))
        # Search ppolicy in LDAP
        try:
            ppolicy = con.search_s(args.ldap_dn_policy, ldap.SCOPE_SUBTREE, "objectclass=*", ['pwdExpireWarning', 'pwdMaxAge', 'pwdLockoutDuration', 'pwdMaxFailure'])
            debug ("Founded ppolicy:"); debug (ppolicy) #ppolicy[0][1]
            pwd_max_age=timedelta(seconds=int(ppolicy[0][1]["pwdMaxAge"][0].decode("utf-8")))
            pwd_expiring_warn=timedelta(seconds=int(ppolicy[0][1]["pwdExpireWarning"][0].decode("utf-8")))
            pwd_lockout_duration=timedelta(seconds=int(ppolicy[0][1]["pwdLockoutDuration"][0].decode("utf-8")))
            pwd_max_failure=int(ppolicy[0][1]["pwdMaxFailure"][0].decode("utf-8"))
            debug ("pwd_max_age = "+str(pwd_max_age)+"| pwd_expiring_warn = "+str(pwd_expiring_warn)+"| pwd_lockout_duration = "+str(pwd_lockout_duration))
        except Exception as e:
            print (e) ; exit (3)
        #Search object in LDAP
        try:
            results = con.search_s(args.ldap_base, ldap.SCOPE_SUBTREE, args.ldap_filter,['*','+'])
            debug ("Founded objects:"); debug (results)
        except Exception as e:
            print (e) ; exit (3)
        
        for object in results:
            if 'mail' in object[1]: # Only check object with 'mail' attrubute
                email_receiver = object[1]["mail"][0].decode("utf-8")

                #Check if account is locked
                if check_locked(object,args.interval_check): 
                    print ("Account "+object[0]+" has been locked")
                    mail_subject = args.mail_subject+" LDAP account has been locked"
                    email_body="Hello,\nYour LDAP account has been locked due to "+str(pwd_max_failure)+" unsuccessful login.\nAccount will be unlocked in "+str(pwd_lockout_duration+" hrs")
                    email_send(args.mail_login,args.mail_from,args.mail_pass,email_receiver,mail_subject,email_body,args.mail_smtp_server,args.mail_smtp_port)

                #Check failed login attempts
                res = check_failed_login(object,args.wrong_count,args.interval_check)
                if res:
                    if (pwd_max_failure-res) > 0:
                        print ("Account "+object[0]+" have failed login attempts: "+str(res))
                        print ("It will be locked after "+str(pwd_max_failure-res)+" attempts")
                        mail_subject = args.mail_subject+" LDAP account login failed"
                        email_body="Hello,\nYou have failed login attempts: "+str(res)+"\nAccount will be locked after "+str(pwd_max_failure-res)+" unsuccessful attempts"
                        email_send(args.mail_login,args.mail_from,args.mail_pass,email_receiver,mail_subject,email_body,args.mail_smtp_server,args.mail_smtp_port)

                #Check password expiration only once day about alert_time
                if abs(datetime.now()-args.alert_time) < args.interval_check:
                    res = check_expiration(object,pwd_max_age,pwd_expiring_warn)
                    if res: 
                        if res > pwd_max_age:
                            print ("Account "+object[0]+" is exipired "+str(res-pwd_max_age)+" ago")
                            mail_subject = args.mail_subject+" LDAP account is disabled"
                            email_body="Hello,\nYour LDAP account has been expired" +str(res-pwd_max_age)+" ago\nPlease contact to LDAP administrator to reset password"
                        else:
                            print ("Account "+object[0]+" will be expired in: "+str(pwd_max_age-res))
                            mail_subject = args.mail_subject+" LDAP account will be expired soon"
                            email_body = "Hello,\nYour LDAP account will be expired in "+str(pwd_max_age-res)+"\nPlease change you password as soon as possible"
                        email_send(args.mail_login,args.mail_from,args.mail_pass,email_receiver,mail_subject,email_body,args.mail_smtp_server,args.mail_smtp_port)

        time.sleep (args.interval_check.seconds)

if __name__ == '__main__':
    main()
