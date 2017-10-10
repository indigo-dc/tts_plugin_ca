#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import json
import base64
import sys
import os
import traceback
import string
import random

OPENSSL_CONF = """
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = %s
new_certs_dir     = \$dir/certs
database          = \$dir/index.txt
certificate       = \$dir/certs/cacert.pem
serial            = \$dir/serial
private_key       = \$dir/private/cakey.pem
crldir            = \$dir/crl
crl               = \$crldir/crl.pem
crlnumber         = \$crldir/crlnumber
default_days      = 365
default_crl_days  = 30
default_md        = sha1
preserve          = no

[ policy_anything ]
countryName             = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional

[ usr_cert ]
subjectKeyIdentifier    =hash
authorityKeyIdentifier  =keyid, issuer
basicConstraints        =CA:FALSE
keyUsage                =digitalSignature, keyEncipherment
"""

VERSION="1.1.0"

def list_params():
    RequestParams = []
    ConfParams = [{'name':'ca_path', 'type':'string', 'default':'/etc/tts/ca'},
                  {'name':'issuer_mapping', 'type':'string', 'default':'{}'},
                  {'name':'ca_subject', 'type':'string', 'default':'/C=EU/O=INDIGO/OU=WATTS/CN=WATTS-CA'},
                  {'name':'cert_valid_duration', 'type':'string', 'default':'11'}]
    return json.dumps({'result':'ok', 'conf_params': ConfParams, 'request_params': RequestParams, 'version':VERSION})

def create_cert(Subject, Issuer, CaPath, NumDaysValid, CASub, IssuerMapping):
    InitCaError = init_ca_if_needed(CaPath, CASub)
    if InitCaError == None:
        Serial = read_serial(CaPath)
        return issue_certificate(Subject, Issuer, CaPath, NumDaysValid, Serial, IssuerMapping)
    else:
        return InitCaError

def revoke_cert(Serial, CaPath, CASub):
    InitCaError = init_ca_if_needed(CaPath, CASub)
    if InitCaError == None:
        return revoke_certificate(Serial, CaPath)
    else:
        return InitCaError

def issue_certificate(Subject, Issuer, AbsBase, NumDaysValid, Serial, IssuerMapping):
    Issuer = Issuer.rstrip('/')
    ShortIss = shorten_issuer(Issuer, IssuerMapping)
    if ShortIss == None:
        LMsg = "unknown issuer '%s'"%Issuer
        UMsg = "sorry, your provider is not supported"
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    Password = id_generator(32)
    CertSubject = SubjectString(Subject, ShortIss, AbsBase)
    AltSub = "subjectAltName = URI:%s/%s"%(Issuer, Subject)
    CAPassFile = "%s/private/pass"%(AbsBase)
    CACertFile = "%s/certs/cacert.pem"%(AbsBase)
    CertFile = "%s/certs/usercert_%s.pem"%(AbsBase, Serial)
    CsrFile = "%s/users/csr/userreq_%s.pem"%(AbsBase, Serial)
    KeyFile = "%s/users/private/userkey_%s.pem"%(AbsBase, Serial)
    PassFile = "%s/users/private/userpass_%s"%(AbsBase, Serial)
    TmpConfFile = "%s/users/private/userconf_%s"%(AbsBase, Serial)
    ConfFile = "%s/openssl.conf"%(AbsBase)
    LogFile = "%s/users/private/userlog_%s"%(AbsBase, Serial)
    Cmd = "echo -n \"%s\" > %s"%(Password, PassFile)

    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "the userpass creation failed: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    Cmd = "openssl req -newkey rsa:1024 -keyout %s -sha256 -out %s -subj \"%s\" -passout file:%s >> %s 2>&1"%(KeyFile, CsrFile, CertSubject, PassFile, LogFile)
    Log = "echo %s > %s"%(Cmd, LogFile)
    os.system(Log)
    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "the csr failed: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    Cmd = "cp %s %s"%(ConfFile, TmpConfFile)
    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "the conf failed: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    Cmd = "echo \"%s\" >> %s"%(AltSub, TmpConfFile)
    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "the conf update failed: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    Cmd = "openssl ca -batch -config %s -days %s -policy policy_anything -extensions usr_cert -out %s -passin file:%s -infiles %s >> %s 2>&1"%(TmpConfFile, NumDaysValid, CertFile, CAPassFile, CsrFile, LogFile)
    Log = "echo %s >> %s"%(Cmd, LogFile)
    os.system(Log)
    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "the sign failed: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    Cert = get_file_content(CertFile)
    CACert = get_file_content(CACertFile)
    PrivKey = get_file_content(KeyFile)
    # Cmd = "shred --remove=wipe %s %s"%(PassFile, KeyFile)
    Cmd = "rm %s %s"%(PassFile, KeyFile)
    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "the file purging failed: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    CertObj = {'name':'Certificate', 'type':'textfile', 'value':Cert, 'rows':30, 'cols':64, 'save_as':'watts_cert.pem'}
    PrivKeyObj = {'name':'Private Key', 'type':'textfile', 'value':PrivKey, 'rows':21, 'cols':64, 'save_as':'watts_cert.key'}
    PasswdObj = {'name':'Passphrase (for Private Key)', 'type':'text', 'value':Password}
    CACertObj = {'name':'CA Certificate', 'type':'textfile', 'value':CACert, 'rows':21, 'cols':64, 'save_as':'watts_ca.crt'}
    Credential = [CertObj, PrivKeyObj, PasswdObj, CACertObj]
    return json.dumps({'result':'ok', 'credential':Credential, 'state':Serial})

def SubjectString(Subject, ShortIss, AbsBase):
    CertPrefixFile = "%s/private/cert_prefix"%AbsBase
    CertPrefix = get_file_content(CertPrefixFile).rstrip('\n')
    SubjectString = "%s/CN=%s@%s"%(CertPrefix, Subject, ShortIss)
    return SubjectString


def shorten_issuer(Issuer, DictJson):
    IssuerDict = json.loads(DictJson)
    if Issuer in IssuerDict:
        return IssuerDict[Issuer]
    return None

def revoke_certificate(Serial, AbsBase):
    LogFile = "%s/users/private/userlog_%s"%(AbsBase, Serial)
    CertFile = "%s/certs/usercert_%s.pem"%(AbsBase, Serial)
    ConfFile = "%s/openssl.conf"%(AbsBase)
    CAPassFile = "%s/private/pass"%(AbsBase)
    CrlFile = "%s/crl/crl.pem"%(AbsBase)
    ConfigPass = "-config %s -passin file:%s"%(ConfFile, CAPassFile)
    Cmd = "openssl ca %s -revoke %s >> %s 2>&1"%(ConfigPass, CertFile, LogFile)
    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "the revoke failed: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    Cmd = "openssl ca -gencrl %s -out %s >> %s 2>&1"%(ConfigPass, CrlFile, LogFile)
    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "the crl failed: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    return json.dumps({'result':'ok'})


def init_ca_if_needed(AbsBase, CASub):
    if not os.path.isdir(AbsBase):
        return init_ca(AbsBase, CASub)
    else:
        return None

def read_serial(AbsBase):
    SerialFile = "%s/serial"%(AbsBase)
    Serial = get_file_content(SerialFile).rstrip('\n')
    return Serial


def init_ca(AbsBase, CASub):
    try:
        os.makedirs("%s"%(AbsBase), 0700)
    except Exception, E:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "init-ca creation of directory %s failed with %s"%(AbsBase, str(E))
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    try:
        os.mkdir("%s/certs"%(AbsBase))
        os.mkdir("%s/private"%(AbsBase))
        os.mkdir("%s/proxies"%(AbsBase))
        os.mkdir("%s/users"%(AbsBase))
        os.mkdir("%s/users/csr"%(AbsBase))
        os.mkdir("%s/users/private"%(AbsBase))
        os.mkdir("%s/crl"%(AbsBase))
    except Exception, E:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "init-ca creation of sub-directories of %s failed with %s"%(AbsBase, str(E))
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    LogFile = "%s/private/ca.log"%(AbsBase)
    Cmd = "touch %s/index.txt > /dev/null"%(AbsBase)
    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "the init-ca touch failed: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    Cmd = "echo \"unique_subject = no\" > %s/index.txt.attr"%(AbsBase)
    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "the init-ca index-attr failed: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    Cmd = "echo \"01\" > %s/serial"%(AbsBase)
    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "the init-ca serial failed: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    Cmd = "echo \"01\" > %s/crl/crlnumber"%(AbsBase)
    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "the init-ca crl-serial failed: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    Config = OPENSSL_CONF%(AbsBase)
    Cmd = "echo \"%s\" > %s/openssl.conf"%(Config, AbsBase)
    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "the init-ca onpenssl.conf failed: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    Password = id_generator(32)
    Cmd = "echo -n \"%s\" > %s/private/pass"%(Password, AbsBase)
    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "the init-ca pass failed: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    Cmd = "openssl req -x509 -newkey rsa:2048 -keyout %s/private/cakey.pem -sha256 -days 3650 -out %s/certs/cacert.pem -subj '%s' -passout file:%s/private/pass -set_serial 0 > %s 2>&1"%(AbsBase, AbsBase, CASub, AbsBase, LogFile)
    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "the init-ca openssl failed: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    CAParts = CASub.split("/")
    del CAParts[-1]
    CertPrefix = "/".join(CAParts)
    Cmd = "echo \"%s\" > %s/private/cert_prefix"%(CertPrefix, AbsBase)
    if os.system(Cmd) != 0:
        UMsg = "an internal error occured, please contact the administrator"
        LMsg = "could not store the CA subject: %s"%Cmd
        return json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})

    return None

def get_file_content(File):
    fo = open(File)
    Content = fo.read()
    fo.close()
    return Content

def id_generator(size=16, chars=string.ascii_uppercase + string.digits+string.ascii_lowercase):
    return ''.join(random.choice(chars) for _ in range(size))


def main():
    UMsg = "an internal error occured, please contact the administrator"
    try:
        Cmd = None
        if len(sys.argv) == 2:
            Json = str(sys.argv[1])+ '=' * (4 - len(sys.argv[1]) % 4)
            JObject = json.loads(str(base64.urlsafe_b64decode(Json)))

            #general information
            Action = JObject['action']

            if Action == "parameter":
                print list_params()
            else:

                State = JObject['cred_state']
                Params = JObject['params']
                ConfParams = JObject['conf_params']
                UserInfo = JObject['user_info']
                Issuer = UserInfo['iss']
                Subject = UserInfo['sub']
                NumDaysValid = ConfParams['cert_valid_duration']
                IssuerMapping = ConfParams['issuer_mapping']
                CASub = ConfParams['ca_subject']
                CaPath = ConfParams['ca_path']
                CaAbsPath = os.path.abspath(os.path.expanduser(CaPath))

                if Action == "request":
                    print create_cert(Subject, Issuer, CaAbsPath, NumDaysValid, CASub, IssuerMapping)
                elif Action == "revoke":
                    print revoke_cert(State, CaAbsPath, CASub)
                else:
                    LMsg = "unknown action %s"%Action
                    print json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})
        else:
            LMsg = "no parameter given to plugin"
            print json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})
    except Exception, E:
        TraceBack = traceback.format_exc(),
        LMsg = "exeption: %s - %s"%(str(E), TraceBack)
        print json.dumps({'result':'error', 'user_msg':UMsg, 'log_msg':LMsg})
        pass

if __name__ == "__main__":
    main()
