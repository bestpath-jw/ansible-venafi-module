#!/usr/bin/python
# -*- coding: utf8 -*-
#
# Ansible Module to Authenticate against Venafi Trust Protection Platform
#
# Copyright: (c) 2018, BestPath <info@bestpath.io>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# Author: BestPath <info@bestpath.io>
# Version: 1.0
# Date: 24-11-2018
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: venafi_retrieval

short_description: Retrieves certificate data from the Venafi Trust Protection Platform.

version_added: "2.5"

description:
    - This is a custom module to allow the retrieval of a certificate from the Venafi Trust Protection Platform store.
    - It provides the ability to download the certificate and if needed the associated private key via RestFul API once the WedSDK feature has been enabled for the user.

notes:
    - For more information refer to the inbuilt Developers Guide https://"{{ ansible_host}}"/Aperture/help/Content/SDK/WebSDK/API%20Reference/cco-sdk-REST-API-reference.htm

author:
    - BestPath (info@bestpath.io)

options:
    hostname:
        description:
            - This is used to control which instance you target to for certificate lookup/retrieval.
            - This can be either and IP address of DNS hostname depending on how your source server is configured.
        required: True
        type: String
    username:
        description:
            - The username required to authenticate to the Venafi Trust Protection Platform. 
        required: True
        type: String
    password:
        description:
            - The password required to authenticate to the Venafi Trust Protection Platform. 
        required: True
        type: String
        no_log: True
    certificate_pwd:
        description:
            - When [include_privatekey=True] this password must be specified to retrieve the private key for the certificate.
            - Must adhere to the password complexity requirements set within the Venafi Trust Protection Platform by the administrator.
            - The default password length is 12 or more alphanumeric characters.
            - The default password complexity requirements mandate that 3 of the following must be fulfilled in addition to the length:
                    - Must contain 'Upper Case'
                    - Must contain 'Lower Case'
                    - Must contain 'Numbers'
                    - Must contain 'Special Characters'
        required: True
        type: String
        no_log: True
    certificate_dn:
        description:
            - The folder in which the certificate resides within the Venafi Trust Protection Platform store.
        required: True
        type: String
    include_privatekey:
        description:
            - This option must be specified if the retrieval of the private key for the certificate is also required.
        default: False
        required: False
        type: String
    include_chain:
        description:
            - This option must be specified if the retrieval of the certificate root chain is needed.
        default: False
        required: False
        type: String
    format:
        description:
            - This option specifies the desired output of the certificate data.
        default: Base64
        required: False
        Choices: [Base64]
    verify_ssl:
        description:
            - This option allows for the bypass of certificate validity.
        default: True
        required: False
        Type: Boolean     
        
'''

EXAMPLES = '''
---
- name: Authenticate & retrieve Certificate & Private Key
  venafi_retrieval:
    hostname: 10.10.10.10
    username: john_doe
    password: SomeSecretPassword
    certificate_pwd: SomeSecretPassword
    certificate_dn: \VED\Policy\Certificates\Fake Folder\Internal\Fake Certificate
    include_privatekey: True
    format: Base64
    verify_ssl: False

- name: Authenticate & retrieve Certificate
  venafi_retrieval:
    hostname: 10.10.10.10
    username: john_doe
    password: SomeSecretPassword
    certificate_dn: \VED\Policy\Certificates\Fake Folder\Internal\Fake Certificate
    
- name: Authenticate & retrieve Certificate
  venafi_retrieval:
    hostname: 10.10.10.10
    username: john_doe
    password: SomeSecretPassword
    certificate_dn: \VED\Policy\Certificates\Fake Folder\Internal\Fake Certificate
    include_chain: True

'''

RETURN = '''
---
current:
  description: The output of collected response data from Venafi Trust Protection Platform after the module has finished
  returned: success
  type: dict
  sample:
        {
            "Certificate_Response": {
                "Certificate": "<certificate_data>",
                "PrivateKey": "<private_key_data>",
                "httpcode": 200,
                "changed": false,
                "failed": false,
                "message": "Certificate and Key Retrieval Successful"
            },
            "Login_Response": {
                "APIKey": "<API_Key_Value>",
                "ValidUntil": "<API_Key_Valid_Until>",
                "httpcode": 200,
                "message": "Login Successful"
            },
            "changed": false,
            "failed": false
        }

error:
  description: The output of error information as returned from the Venafi Trust Protection Platform.
  returned: failure
  type: dict
  sample:
        {
            "changed": false, 
            "message": "The certificate password complexity has not been meet", 
            "msg": "Login failed"
        }
        
'''

from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
import json
import re
from urllib2 import URLError


def password_complexity_check(certificate_pwd):

    if len(certificate_pwd) < 12:
        password_check = dict(
            changed=False,
            failed=True,
            message="The certificate password must be more than 12 characters in length",
        )          
        return password_check
    
    password_strength = []
    if re.search(r'[A-Z]', certificate_pwd):
        password_strength.append(True)
    if re.search(r'[a-z]', certificate_pwd):
        password_strength.append(True)
    if re.search(r'[0-9]', certificate_pwd):
        password_strength.append(True)
    if re.search(r'[!"£$%^&*()]', certificate_pwd):
        password_strength.append(True)
    
    if len(password_strength) < 3:
        password_check = dict(
            changed=False,
            failed=True,
            message="The certificate password complexity has not been meet",
        )          
        return password_check
    else:
        password_check = dict(
            changed=False,
            failed=False,
        )          
        return password_check

        
def venafi_login(hostname, username, password, headers, verify_ssl):

    request_type = 'POST'
    payload = {'Username': username, 'Password': password}
    url = 'https://{0}/vedsdk/authorize/'.format(hostname)
    
    try:
        request = open_url(
            url.replace(" ", '%20'),
            method=request_type,
            data=json.dumps(payload),
            validate_certs=verify_ssl,
            headers=headers
        )
        APIKey = json.load(request)
        httpcode = request.getcode()

        if httpcode == 200:       
            APIKey['message'] = "Login Successful"
            APIKey['httpcode'] = httpcode
        else:
            APIKey['changed'] = False
            APIKey['failed'] = True
            APIKey['message'] = "Either parameter 'password' or 'username' has been entered incorrectly, or the account is locked out"
            APIKey['httpcode'] = httpcode
        
    except URLError as urlerror:
        APIKey = dict(
            url=url,
            method=request_type,
            validate_certs=verify_ssl,
            urlerror=urlerror.read(),
            message="Either parameter 'password' or 'username' has been entered incorrectly, or the account is locked out",
            httpcode=None
        ) 

    return APIKey

        
def venafi_certificate_retrieval(hostname, headers, token, certificate_dn, format, include_privatekey, include_chain, certificate_pwd, verify_ssl):
    
    request_type = 'GET'
    if include_privatekey == 'False' and include_chain == 'False':
        url = 'https://{0}/vedsdk/Certificates/Retrieve?apikey={1}&CertificateDN={2}&Format={3}'.format(hostname, token, certificate_dn, format)
    elif include_privatekey == 'True' and include_chain == 'False':
        url = 'https://{0}/vedsdk/Certificates/Retrieve?apikey={1}&CertificateDN={2}&Format={3}&Password={4}&IncludePrivateKey={5}'.format(hostname, token, certificate_dn, format, certificate_pwd, include_privatekey)
    elif include_privatekey == 'False' and include_chain == 'True':
        url = 'https://{0}/vedsdk/Certificates/Retrieve?apikey={1}&CertificateDN={2}&Format={3}&IncludeChain={4}'.format(hostname, token, certificate_dn, format, include_chain)
    else: 
        url = 'https://{0}/vedsdk/Certificates/Retrieve?apikey={1}&CertificateDN={2}&Format={3}&Password={4}&IncludePrivateKey={5}&IncludeChain={6}'.format(hostname, token, certificate_dn, format, certificate_pwd, include_privatekey, include_chain)

    try:
        request = open_url(
            url.replace(" ", '%20'),
            method=request_type,
            validate_certs=verify_ssl,
            headers=headers
        )
        
        CertificateData = dict(
            changed=False,
            failed=False
        )
        httpcode = request.getcode()
        RequestData = "".join(request.readlines())
        
        if httpcode == 200:
            if include_privatekey == 'False' and include_chain == 'False':
                certificate = RequestData
                
                CertificateData['message'] = "Certificate Retrieval Successful"
                CertificateData['httpcode'] = httpcode
                CertificateData['Certificate'] = certificate
                    
            elif include_privatekey == 'True' and include_chain == 'False':
                certificate = RequestData.split('-----END CERTIFICATE-----', 1)[0] + '-----END CERTIFICATE-----'
                privatekey = RequestData.split('-----END CERTIFICATE-----', 1)[1]    
                
                CertificateData['message'] = "Certificate and Key Retrieval Successful"
                CertificateData['httpcode'] = httpcode
                CertificateData['Certificate'] = certificate            
                CertificateData['PrivateKey'] = privatekey   
        
            elif include_privatekey == 'False' and include_chain == 'True':
                certificate_data = RequestData.split('-----END CERTIFICATE-----', 1)[0] + '-----END CERTIFICATE-----'
                certificate_chain = RequestData.split('-----END CERTIFICATE-----', 1)[1]
                certificate = certificate_chain + certificate_data
                
                CertificateData['message'] = "Certificate and Certificate Chain Retrieval Successful"
                CertificateData['httpcode'] = httpcode
                CertificateData['Certificate'] = certificate                       
                
            else:
                certificate_data = RequestData.split('-----END CERTIFICATE-----', 1)[0] + '-----END CERTIFICATE-----'
                certificate_chain = RequestData.split('-----END CERTIFICATE-----', 1)[1].split('-----BEGIN RSA PRIVATE KEY-----')[0]
                certificate = certificate_chain + certificate_data
                privatekey = '-----BEGIN RSA PRIVATE KEY-----' + RequestData.split('-----BEGIN RSA PRIVATE KEY-----')[1]
        
                CertificateData['message'] = "Certificate, Certificate Chain and Private Key Retrieval Successful"
                CertificateData['httpcode'] = httpcode
                CertificateData['Certificate'] = certificate            
                CertificateData['PrivateKey'] = privatekey
        
    except URLError as urlerror:
        CertificateData = dict(
            url=url,
            method=request_type,
            validate_certs=verify_ssl,
            urlerror=urlerror.read(),
            message="Certificate Data retrieval has failed",
            httpcode=None
        )
    
    return CertificateData
        

def main():

    module_args = dict(
        hostname=dict(required=True, type='str'),
        username=dict(required=True, type='str'),
        password=dict(required=True, type='str', no_log=True),
        certificate_pwd=dict(required=False, type='str'),
        certificate_dn=dict(required=True, type='str'),
        include_privatekey=dict(default=False, required=False, type='str'),
        include_chain=dict(default=False, required=False, type='str'),
        format=dict(default='Base64', required=False, choices=['Base64']),
        verify_ssl=dict(default=True, required=False, type='bool')
    )
    
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )
	
    hostname = module.params['hostname']
    username = module.params['username']
    password = module.params['password']
    certificate_dn = module.params['certificate_dn']
    format = module.params['format']
    include_privatekey = module.params['include_privatekey']
    include_chain = module.params['include_chain']
    certificate_pwd = module.params['certificate_pwd']
    headers = {'Content-Type': 'application/json'}
    verify_ssl = module.params['verify_ssl']

    APIKey = venafi_login(hostname, username, password, headers, verify_ssl)

    if include_privatekey == 'True' and certificate_pwd is None:
        NoCertificatePassword = dict(
            changed=False,
            failed=True,
            message="You have failed to specify a password for the certificate download to work",
        )        
        module.exit_json(**NoCertificatePassword)
    elif include_privatekey == 'True' and certificate_pwd is not None:
        password_check = password_complexity_check(certificate_pwd)
        if password_check['failed'] == True:
            module.exit_json(**password_check)

    if APIKey['httpcode'] == 200:
        token = APIKey['APIKey']
        CertificateData = venafi_certificate_retrieval(hostname, headers, token, certificate_dn, format, include_privatekey, include_chain, certificate_pwd, verify_ssl)
    else:
        module.fail_json(msg='Login failed', **APIKey)

    if CertificateData['httpcode'] == 200:
        result = dict(
            changed=False,
            Login_Response=APIKey,
            Certificate_Response=CertificateData,
        )
        module.exit_json(**result)
    else:
        module.fail_json(msg='Failed to retrieve Certificate Data', **CertificateData)     
    
if __name__ == '__main__':
    main()
