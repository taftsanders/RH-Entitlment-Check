#!/usr/bin/python

'''
This is a pseduo application to check the serial of an entitlement for any changes

Typically a system profile can be created without subscription-manager on access.redhat.com
and entitlements can be attached to this profile and exported to alternate applications.

Another method of accomplishing this could be to create a subscription-allocation profile
and attach entitlements to this profile and export to alternate applications as well.

Both methods should produce the same end results which is to have an x509 certificate and key
with an additional field called "entitlement data" appended to it. The serial number of the
certificate is given in each certificate and also matches the name of the certificate as seen
below:
# rct cat-cert /etc/pki/entitlement/1322767459633761921.pem | grep Serial
	Serial: 1322767459633761921

If a certificate is revoked for any reason the serial number is the key that is used to identify
the certificates validaty. If this number changes, the previous certificate should be considered
invalid and a new certificate will be required to access content.

As artifactory is deployable on systems where subscription-manager is not, it would be best to
write the process for this without using libraries from subscription-manager.
'''

import requests
import sys
import zipfile
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# All RHSM API requests will require an offline token that is good (until 30 days of inactivity) to request a token
# https://access.redhat.com/management/api
RHSM_ENDPOINT='https://subscription.rhsm.redhat.com'
TMPDIR = '/tmp/'

# CA = the Red Hat CA from any RHEL system found at /etc/rhsm/ca/redhat-uep.pem
# idcert = the x509 identity certificate you get when registering (found in /etc/pki/consumer/cert.pem) or the identity cert downloaded from the customer portal profile
# idkey = the key for the idcert
# subSerial = the previous serial number from the previous subscription. This will be used for verification purposes only. 
# If one is not provided it will assume the serial is not present or expired and pull a new one.

def main(CA=None,idcert=None,idkey=None,subSerial=None):
    # Must pass in CA,idcert,idkey at minimum
    # If subSerial is not empty verify the serials with those collected from the profile
    
    # Verify the host profile still exists
    if CA != None and idcert != None and idkey != None:
        cpid = get_consumer_uuid(idcert)
        rhsm_certificates = get_rhsm_certificates(CA,idcert,idkey,cpid)
        serials = get_rhsm_serials(rhsm_certificates,idcert,idkey,CA,cpid)
        try:
            if subSerial != None:
                if subSerial in serials:
                    print('%s Serial still valid' %subSerial)
                    if len(subSerial) != len(serials):
                        print('More entitlements exist on the profile than provided')
                        print('Pulling certificates and keys for remaining subscriptions')
                        serials.remove(subSerial)
                        new_subscriptions = extract_certificates(rhsm_certificates,idcert,idkey,CA,serials,cpid)
                        print(new_subscriptions)
                    else:
                        print('No new subscriptions to be added')
                else:
                    print('Current serial %s is no longer valid' %subSerial)
                    print('Pulling new certificates')
                    new_subscriptions = extract_certificates(rhsm_certificates,idcert,idkey,CA,serials,cpid)
                    print(new_subscriptions)
            else:
                print('No serials provided by user, all certificates will be provided from the profile')
                new_subscriptions = extract_certificates(rhsm_certificates,idcert,idkey,CA,serials,cpid)
                print(new_subscriptions)
        except:
            print('Failed to gather list of new subcriptions')
    else:
        print("You failed to provide either the Red Hat CA cert, identity cert, or identity key")


def get_consumer_uuid(idcert):
# From the cert path provided, extract the consumer UUID from the cert and return the string
    try:
        with open(idcert) as cert:
            identity_cert = cert.read()
            identity_cert = x509.load_pem_x509_certificate(identity_cert.encode('ascii'), default_backend())
            cpid = identity_cert.subject.rfc4514_string()[3:].split(',')[0]
            return cpid
    except Exception as e:
        print('Failed to read system identity certificate with error: %s' % e)


def get_rhsm_serials(rhsm_certificates,idcert,idkey,CA,cpid):
    # Extract the serial numbers for the subscriptions attached to the profile
    try:
        serials = []
        # If SCA is enabled, no subscriptions could be attached to the profile
        resp = requests.get(RHSM_ENDPOINT+'/subscription/consumers/'+cpid+'/certificates/serials',
            verify = CA, cert = (idcert, idkey)).json()
        for i in range(len(resp)):
            serial = resp[i]['serial']
            serials.append(serial)
        return serials
    except Exception as e:
        print('Failed to extract the serials from the certificates with: %s' % e)


def extract_certificates(rhsm_certificates,idcert,idkey,CA,serials,cpid):
    # Get the entitlement for each serial specified
    # for serial in list
    subscriptions= []
    files = []
    URL = RHSM_ENDPOINT+'/subscription/consumers/'+cpid+'/certificates?serials='
    for serial in serials:
        ent = requests.get(URL+str(serial), verify=CA, cert=(idcert,idkey))
        files.append(str(serial)+'.zip')
        open(str(serial)+'.zip', 'wb').write(ent.content)
    for file in files:
        with zipfile.ZipFile(file, 'r') as L1:
            L1.extract('consumer_export.zip',TMPDIR)
        with zipfile.ZipFile('/tmp/consumer_export.zip') as L1:
            for zfile in L1.infolist():
                if zfile.filename.endswith('.pem'):
                    L1.extract(zfile,TMPDIR)
                    subscriptions.append(TMPDIR+zfile.filename)
    return subscriptions


def get_rhsm_certificates(CA,idcert,idkey,cpid):
    # Grab the serials for the entitlements on the profile for comparison
    try:
        rhsm_certificates = requests.get(RHSM_ENDPOINT+'/subscription/consumers/'+cpid+'/entitlements',
            verify = CA, cert = (idcert, idkey))
        return rhsm_certificates
    except Exception as e:
        print('Failed to access profile certificate from subcription.rhsm.redhat.com with the error: %s' % e)
        exit


if __name__=="__main__":
    main(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])