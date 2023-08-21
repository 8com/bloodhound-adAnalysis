"""
Copyright (C) 2023 Robin Meier

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import hmac
import hashlib
import base64
import requests
#import datetime

from neo4j import GraphDatabase, RoutingControl
from neo4j.exceptions import DriverError, Neo4jError
from datetime import datetime, date, time, timezone
import csv
import time

import argparse
import glob

from typing import Optional

# this API section is taken (and modified) from the python script provided in https://support.bloodhoundenterprise.io/hc/en-us/articles/11311053342619-Working-with-the-BloodHound-API
BHE_DOMAIN = "localhost"
BHE_PORT = 8080
BHE_SCHEME = "http"
BHE_TOKEN_ID = "<YOUR TOKEN ID HERE>"
BHE_TOKEN_KEY = "<YOUR TOKEN KEY HERE>"

PRINT_PRINCIPALS = False
PRINT_ATTACK_PATH_TIMELINE_DATA = False
PRINT_POSTURE_DATA = False

DATA_START = "1970-01-01T00:00:00.000Z"
DATA_END = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z' # Now

class Credentials(object):
    def __init__(self, token_id: str, token_key: str) -> None:
        self.token_id = token_id
        self.token_key = token_key

class Domain(object):
    def __init__(self, name: str, id: str, collected: bool, domain_type: str) -> None:
        self.name = name
        self.id = id
        self.type = domain_type
        self.collected = collected

class APIVersion(object):
    def __init__(self, api_version: str, server_version: str) -> None:
        self.api_version = api_version
        self.server_version = server_version

class Client(object):
    def __init__(self, scheme: str, host: str, port: int, credentials: Credentials) -> None:
        self._scheme = scheme
        self._host = host
        self._port = port
        self._credentials = credentials

    def _format_url(self, uri: str) -> str:
        formatted_uri = uri
        if uri.startswith("/"):
            formatted_uri = formatted_uri[1:]

        return f"{self._scheme}://{self._host}:{self._port}/{formatted_uri}"

    def _request(self, method: str, uri: str, body: Optional[bytes] = None) -> requests.Response:
        # Digester is initialized with HMAC-SHA-256 using the token key as the HMAC digest key.
        digester = hmac.new(self._credentials.token_key.encode(), None, hashlib.sha256)

        # OperationKey is the first HMAC digest link in the signature chain. This prevents replay attacks that seek to
        # modify the request method or URI. It is composed of concatenating the request method and the request URI with
        # no delimiter and computing the HMAC digest using the token key as the digest secret.
        #
        # Example: GET /api/v1/test/resource HTTP/1.1
        # Signature Component: GET/api/v1/test/resource
        digester.update(f"{method}{uri}".encode())

        # Update the digester for further chaining
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        # DateKey is the next HMAC digest link in the signature chain. This encodes the RFC3339 formatted datetime
        # value as part of the signature to the hour to prevent replay attacks that are older than max two hours. This
        # value is added to the signature chain by cutting off all values from the RFC3339 formatted datetime from the
        # hours value forward:
        #
        # Example: 2020-12-01T23:59:60Z
        # Signature Component: 2020-12-01T23
        datetime_formatted = datetime.now().astimezone().isoformat("T")
        digester.update(datetime_formatted[:13].encode())

        # Update the digester for further chaining
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        # Body signing is the last HMAC digest link in the signature chain. This encodes the request body as part of
        # the signature to prevent replay attacks that seek to modify the payload of a signed request. In the case
        # where there is no body content the HMAC digest is computed anyway, simply with no values written to the
        # digester.
        if body is not None:
            digester.update(body)

        # Perform the request with the signed and expected headers
        return requests.request(
            method=method,
            url=self._format_url(uri),
            headers={
                "User-Agent": "bhe-python-sdk 0001",
                "Authorization": f"bhesignature {self._credentials.token_id}",
                "RequestDate": datetime_formatted,
                "Signature": base64.b64encode(digester.digest()),
                "Content-Type": "application/json",
            },
            data=body,
        )

    def get_version(self) -> APIVersion:
        response = self._request("GET", "/api/version")
        payload = response.json()

        return APIVersion(api_version=payload["data"]["API"]["current_version"], server_version=payload["data"]["server_version"])

def connectToApi():
    # This might be best loaded from a file
    credentials = Credentials(
        token_id=BHE_TOKEN_ID,
        token_key=BHE_TOKEN_KEY,
    )

    # Create the client and perform an example call using token request signing
    client = Client(scheme=BHE_SCHEME, host=BHE_DOMAIN, port=BHE_PORT, credentials=credentials)
    return client

def getApiVersion(client):
    version = client.get_version()

    print("BHE Python API Client Example")
    print(f"API version: {version.api_version} - Server version: {version.server_version}\n")

def getAvailableDomains(client) -> list[Domain]:
    response = client._request('GET', '/api/v2/available-domains')
    payload = response.json()['data']

    domains = list()
    for domain in payload:
        domains.append(Domain(domain["name"], domain["id"], domain["collected"], domain["type"]))
    for domain in domains:
        print(f'{domain.name} : {domain.id}')
    return domains

# end of API section

def getDomainInfo(client, dom_id):
    response = client._request('GET', f'/api/v2/ad-domains/{dom_id}/data-quality-stats')
    payload = response.json()['data'][0]
    return (payload['users'], payload['groups'], payload['computers'], payload['ous'], payload['gpos'])

def uploadData(client, dirToJson):
    postfix = ['_ous.json', '_gpos.json', '_containers.json', '_computers.json', '_groups.json', '_users.json', '_domains.json']
    response = client._request('POST', '/api/v2/file-upload/start')
    uploadId = response.json()['data']['id']
    for file in postfix:
        filename = glob.glob(dirToJson + '/*' + file)
        print(f'Uploading: {filename[0]}')
        with open(filename[0], 'r', encoding='utf-8-sig') as f:
            data = f.read().encode('utf-8')
            response = client._request('POST', f'/api/v2/file-upload/{uploadId}', data)
    response = client._request('POST', f'/api/v2/file-upload/{uploadId}/end')
    print('Waiting for BloodHound to ingest the data.')
    response = client._request('GET', '/api/v2/file-upload?skip=0&limit=10&sort_by=-id')
    status = response.json()['data'][0]
    while True:
        if status['id'] == uploadId and status['status_message'] == "Complete":
            break
        else:
            time.sleep(15)
            response = client._request('GET', '/api/v2/file-upload?skip=0&limit=10&sort_by=-id')
            status = response.json()['data'][0]
    print('Done! Continuing now.')

def collectBasicInfos(driver, apiInput):
    print('===+++===+++===+++===+++===')
    print('    Collecting Basic Information')
    print('===+++===+++===+++===+++===')
    totalUsers = apiInput[0]
    print(f'There is a total of {totalUsers} Users')
    totalComputers = apiInput[2]
    print(f'There is a total of {totalComputers} Computers')
    totalGroups = apiInput[1]
    print(f'There is a total of {totalGroups} Groups')
    totalOUs = apiInput[3]
    print(f'There is a total of {totalOUs} OUs')
    totalGPOs = apiInput[4]
    print(f'There is a total of {totalGPOs} GPOs')
    return (totalUsers, totalComputers)

def writeCsvFile(filename, data):
    fullFilename = filename
    with open(fullFilename, 'w', newline='') as f:
        csvwriter = csv.writer(f, delimiter=',')
        for line in data:
            csvwriter.writerow(line)

def writeUsersList(data, filename):
    with open(filename, 'w') as f:
        for i in data:
            f.write(i["u.name"] + '\n')

def printBanner(title):
    print('===+++===+++===+++===+++===')
    print(f'    {title}')
    print('===+++===+++===+++===+++===')

def genUserLists(driver):
    printBanner('Generating User Lists')
    q = "MATCH (u:User) WHERE u.enabled = true RETURN u.name"
    enabledUsers, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
    q2 = "MATCH (u:User) WHERE u.enabled = true AND u.system_tags = 'admin_tier_0' RETURN u.name"
    enabledTierZeroUsers, _, _ = driver.execute_query(q2, database_="neo4j", routing_=RoutingControl.READ)
    q3 = "MATCH (u:User) WHERE u.enabled = true AND u.lastlogon < (datetime().epochseconds - (90 * 86400)) AND u.lastlogontimestamp < (datetime().epochseconds - (90 * 86400)) RETURN u.name"
    enabledInactiveUsers, _, _ = driver.execute_query(q3, database_="neo4j", routing_=RoutingControl.READ)
    q4 = "MATCH (u:User) WHERE (u.name =~ '(?i).*adm.*' OR u.description =~ '(?i).*admin.*') AND u.enabled = true RETURN u.name "
    enabledPotentialAdminUsers, _, _ = driver.execute_query(q4, database_="neo4j", routing_=RoutingControl.READ)
    print(f'Writing EnabledUsersList with {len(enabledUsers)} users to: enabledUsers.txt')
    writeUsersList(enabledUsers, 'enabledUsers.txt')
    print(f'Writing EnabledTierZeroUsersList with {len(enabledTierZeroUsers)} users to: enabledTierZeroUsers.txt')
    writeUsersList(enabledTierZeroUsers, 'enabledTierZeroUsers.txt')
    print(f'Writing EnabledInactiveUsersList with {len(enabledInactiveUsers)} users to: enabledInactiveUsers.txt')
    writeUsersList(enabledInactiveUsers, 'enabledInactiveUsers.txt')
    print(f'Writing EnabledPotentialAdminUsers with {len(enabledPotentialAdminUsers)} users to: enabledPotentialAdminUsers.txt')
    writeUsersList(enabledPotentialAdminUsers, 'enabledPotentialAdminUsers.txt')

def checkLaps(driver):
    printBanner('Checking LAPS')
    q = "MATCH (c:Computer) WHERE c.haslaps = false AND c.enabled = true RETURN count(c) "
    noLaps, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
    q2 = "MATCH (c:Computer) WHERE (c.lastlogon > (datetime().epochseconds - (90 * 86400)) OR c.lastlogontimestamp > (datetime().epochseconds - (90 * 86400))) AND c.haslaps = false AND c.enabled = true RETURN count(c)"
    criticalNoLaps, _, _ = driver.execute_query(q2, database_="neo4j", routing_=RoutingControl.READ)
    print(f'There are {noLaps[0]["count(c)"]} enabled Computers without LAPS! {criticalNoLaps[0]["count(c)"]} seem to be in active use!')
    if noLaps[0]["count(c)"] > 0:
        print("Generating csv-file for: Affected Resources")
        affectedResourcesLaps, _, _ = driver.execute_query(
            "MATCH (c:Computer) "
            "WHERE c.haslaps = false AND c.enabled = true "
            "RETURN c.name, c.objectid ",
            database_="neo4j", routing_=RoutingControl.READ,
        )
        writeCsvFile('laps.csv', affectedResourcesLaps)

def checkUnsupportedOs(driver):
    printBanner('Checking Unsupported OS')
    q = "MATCH (c:Computer) WHERE c.operatingsystem =~ '(?i).*(2000|2003|2008|xp|vista|7|me).*' AND (c.lastlogon > (datetime().epochseconds - (90 * 86400)) OR c.lastlogontimestamp > (datetime().epochseconds - (90 * 86400))) AND c.enabled = true RETURN count(c)"
    unsupportedOs, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
    print(f'There are {unsupportedOs[0]["count(c)"]} active computers with an unsupported OS.')
    if unsupportedOs[0]["count(c)"] > 0:
        print("Generating csv-file for: Affected Resources")
        q2 = "MATCH (c:Computer) WHERE c.operatingsystem =~ '(?i).*(2000|2003|2008|xp|vista|7|me).*' AND (c.lastlogon > (datetime().epochseconds - (90 * 86400)) OR c.lastlogontimestamp > (datetime().epochseconds - (90 * 86400))) AND c.enabled = true RETURN c.name, c.objectid"
        affectedResourcesUnsupportedOs, _, _ = driver.execute_query(q2, database_="neo4j", routing_=RoutingControl.READ)
        outfile = 'unsupportedOs.csv'
        writeCsvFile('unsupportedOs.csv', affectedResourcesUnsupportedOs)

def checkInactiveUsersAndComputers(driver, totalUsers, totalComputers):
    printBanner('Checking inactive Users/Computers')
    q = "MATCH (u:User) WHERE u.lastlogon < (datetime().epochseconds - (90 * 86400)) AND u.lastlogontimestamp < (datetime().epochseconds - (90 * 86400)) AND u.samaccountname <> 'krbtgt' RETURN count(u) "
    inactiveUsers, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
    print(f'There are {inactiveUsers[0]["count(u)"]} users marked as inactive out of {totalUsers}!')
    inactiveEnabledUsers, _, _ = driver.execute_query(
        "MATCH (u:User) "
        "WHERE u.lastlogon < (datetime().epochseconds - (90 * 86400)) AND "
        "u.lastlogontimestamp < (datetime().epochseconds - (90 * 86400)) AND "
        "u.samaccountname <> 'krbtgt' AND "
        "u.enabled = true "
        "RETURN count(u) ",
        database_="neo4j", routing_=RoutingControl.READ,
    )
    print(f'Out of these {inactiveUsers[0]["count(u)"]} inactive users {inactiveEnabledUsers[0]["count(u)"]} are still enabled!')
    print("Generating csv-file for: Affected Resources")
    affectedResourcesInactiveUsers, _, _ = driver.execute_query(
        "MATCH (u:User) "
        "WHERE u.lastlogon < (datetime().epochseconds - (90 * 86400)) AND "
        "u.lastlogontimestamp < (datetime().epochseconds - (90 * 86400)) AND "
        "u.samaccountname <> 'krbtgt' "
        "RETURN u.name, u.objectid, u.enabled, u.admincount ",
        database_="neo4j", routing_=RoutingControl.READ,
    )
    writeCsvFile('inactiveUsers.csv', affectedResourcesInactiveUsers)

    q2 = "MATCH (c:Computer) WHERE c.lastlogon < (datetime().epochseconds - (90 * 86400)) AND c.lastlogontimestamp < (datetime().epochseconds - (90 * 86400)) RETURN count(c) "
    inactiveComputers, _, _ = driver.execute_query(q2, database_="neo4j", routing_=RoutingControl.READ)
    print(f'There are {inactiveComputers[0]["count(c)"]} computers marked as inactive out of {totalComputers}!')
    inactiveEnabledComputers, _, _ = driver.execute_query(
        "MATCH (u:Computer) "
        "WHERE u.lastlogon < (datetime().epochseconds - (90 * 86400)) AND "
        "u.lastlogontimestamp < (datetime().epochseconds - (90 * 86400)) AND "
        "u.enabled = true "
        "RETURN count(u) ",
        database_="neo4j", routing_=RoutingControl.READ,
    )
    print(f'Out of these {inactiveComputers[0]["count(c)"]} inactive computers {inactiveEnabledComputers[0]["count(u)"]} are still enabled!')
    print("Generating csv-file for: Affected Resources")
    affectedResourcesInactiveComputers, _, _ = driver.execute_query(
        "MATCH (c:Computer) "
        "WHERE c.lastlogon < (datetime().epochseconds - (90 * 86400)) AND "
        "c.lastlogontimestamp < (datetime().epochseconds - (90 * 86400)) "
        "RETURN c.name, c.objectid, c.enabled ",
        database_="neo4j", routing_=RoutingControl.READ,
    )
    writeCsvFile('inactiveComputers.csv', affectedResourcesInactiveComputers)

def checkKrbtgtPassword(driver):
    printBanner('Checking krbtgt Password')
    q = "MATCH (u:User) WHERE u.samaccountname = 'krbtgt' RETURN u.pwdlastset "
    krbtgtPassword, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
    currentTime = datetime.now()
    krbtgtPasswordTime = datetime.fromtimestamp(krbtgtPassword[0]["u.pwdlastset"])
    krbtgtPasswordTimeStr = krbtgtPasswordTime.strftime('%d.%m.%Y %H:%M:%S')
    timeDiffInDays = (currentTime - krbtgtPasswordTime).days
    print(f'The krbtgt Password was last set on {krbtgtPasswordTimeStr} which means it is {timeDiffInDays} days old! If the password is over 180 days old it should be changed!')

def checkSensitiveAccountsAndProtectedUsers(driver):
    printBanner('Checking DA Count')
    q = "MATCH p=(n:Group)<-[:MemberOf*1..]-(m:User) WHERE n.objectid ENDS WITH '-512' WITH COLLECT(m) AS das \nMATCH (u:User) WHERE u IN das RETURN count(u) "
    totalDAs, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
    q2 = "MATCH p=(n:Group)<-[:MemberOf*1..]-(m:User) WHERE n.objectid ENDS WITH '-512' WITH COLLECT(m) AS das \nMATCH (u:User) WHERE u IN das AND u.enabled = true RETURN count(u) "
    totalDAsEnabled, _, _ = driver.execute_query(q2, database_="neo4j", routing_=RoutingControl.READ)
    print("Generating csv-file for: Affected Resources")
    affectedResourcesDas, _, _ = driver.execute_query(
        "MATCH p=(n:Group)<-[:MemberOf*1..]-(m:User) WHERE n.objectid ENDS WITH '-512' WITH COLLECT(m) AS das MATCH (u:User) WHERE u IN das RETURN u.name, u.objectid ",
        database_="neo4j", routing_=RoutingControl.READ,
    )
    writeCsvFile('domainAdmins.csv', affectedResourcesDas)
    print(f'There is a total of {totalDAs[0]["count(u)"]} Domain Admin Users ({totalDAsEnabled[0]["count(u)"]} enabled). The number of Domain Admins should be kept as low as possible.')


    printBanner('Checking Tier Zero Count')
    q = "MATCH (n:User) WHERE n.system_tags='admin_tier_0' RETURN count(n) "
    totalTierZeroUsers, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
    q2 = "MATCH (n:User) WHERE n.system_tags='admin_tier_0' AND n.enabled = true RETURN count(n) "
    totalTierZeroUsersEnabled, _, _ = driver.execute_query(q2, database_="neo4j", routing_=RoutingControl.READ)
    print(f'There is a total of {totalTierZeroUsers[0]["count(n)"]} Tier Zero users ({totalTierZeroUsersEnabled[0]["count(n)"]} enabled). The number of Tier Zero users should be kept as low as possible.')
    print("Generating csv-file for: Affected Resources")
    affectedResourcesTierZero, _, _ = driver.execute_query(
        "MATCH (n:User) WHERE n.system_tags='admin_tier_0' RETURN n.name, n.objectid ",
        database_="neo4j", routing_=RoutingControl.READ,
    )
    writeCsvFile('tierZeroUsers.csv', affectedResourcesTierZero)

    printBanner('Checking Protected Users')
    q = "MATCH (u:User)-[:MemberOf]->(g:Group) WHERE g.objectid ENDS WITH '-525' RETURN count(u) "
    protectedUsers, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
    print(f'The group Protecetd Users has {protectedUsers[0]["count(u)"]} members. It is recommended that at least all Tier Zero Users (here: {totalTierZeroUsers[0]["count(n)"]}) should be in this group!')

def checkActiveGuest(driver):
    printBanner('Checking Guest Account')
    q = "MATCH (u:User) WHERE u.objectid ENDS WITH '-501' RETURN u.name, u.enabled, u.lastlogon, u.lastlogontimestamp "
    guest, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
    if guest[0]["u.enabled"] == "TRUE":
        print('The Guest Account is enabled which is not recommended.')
    else:
        print('The Guest Account is disabled.')

def checkKerberoastableUsers(driver):
    printBanner('Checking Kerberoastable Users')
    q = "MATCH (n:User) WHERE n.hasspn=true AND n.samaccountname <> 'krbtgt' RETURN count(n) "
    kerberoastable, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
    q2 = "MATCH (n:User) WHERE n.hasspn=true AND n.samaccountname <> 'krbtgt' AND n.system_tags='admin_tier_0' RETURN count(n) "
    kerberoastableTierZero, _, _ = driver.execute_query(q2, database_="neo4j", routing_=RoutingControl.READ)
    print(f'There is a total of {kerberoastable[0]["count(n)"]} kerberoastable Users. This includes {kerberoastableTierZero[0]["count(n)"]} Tier Zero Accounts!')
    if kerberoastable[0]["count(n)"] > 0:
        print("Generating csv-file for: Affected Resources")
        q3 = "MATCH (n:User) WHERE n.hasspn=true AND n.samaccountname <> 'krbtgt' RETURN n.name, n.objectid, n.serviceprincipalnames, n.system_tags "
        kerberoastableData, _, _ = driver.execute_query(q3, database_="neo4j", routing_=RoutingControl.READ)
        writeCsvFile('kerberoastableUsers.csv', kerberoastableData)
        
def checkAsrepRoasting(driver):
    printBanner('Checking AS-REP Roastable Users')
    q = "MATCH (u:User) WHERE u.dontreqpreauth = true RETURN count(u) "
    asreproastable, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
    print(f'There is a total of {asreproastable[0]["count(u)"]} AS-REP roastable Users')
    if asreproastable[0]["count(u)"] > 0:
        print("Generating csv-file for: Affected Resources")
        asreproastableData, _, _ = driver.execute_query(
            "MATCH (u:User) "
            "WHERE u.dontreqpreauth = true "
            "RETURN u.name, u.objectid, u.system_tags ",
            database_="neo4j", routing_=RoutingControl.READ,
        )
        writeCsvFile('asrepRoastableUsers.csv', asreproastableData)

def checkTierZeroSessions(driver):
    printBanner('Checking Tier Zero Sessions')
    q = "MATCH (u:User) WHERE u.system_tags='admin_tier_0' MATCH p = (c:Computer)-[:HasSession]->(u:User) RETURN count(p), count(DISTINCT u), count(DISTINCT c) "
    tierZeroSessions, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
    print(f'There is a total of {tierZeroSessions[0]["count(p)"]} active Tier Zero sessions. From {tierZeroSessions[0]["count(DISTINCT u)"]} Users on {tierZeroSessions[0]["count(DISTINCT c)"]} Systems')
    if tierZeroSessions[0]["count(p)"] > 0:
        print("Generating csv-file for: Affected Resources")
        q2 = "MATCH (u:User) WHERE u.system_tags='admin_tier_0' MATCH p = (c:Computer)-[:HasSession]->(u:User) RETURN u.name, u.objectid, c.name, c.objectid "
        tierZeroSessionsData, _, _ = driver.execute_query(q2, database_="neo4j", routing_=RoutingControl.READ)
        writeCsvFile('tierZeroSessions.csv', tierZeroSessionsData)

def checkDcSync(driver):
    printBanner('Checking DCSync (non Tier Zero)')
    q = "MATCH p=(n)-[:DCSync|AllExtendedRights|GenericAll]->(:Domain) WHERE NOT n.system_tags='admin_tier_0' RETURN count(n) "
    dcsync, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
    print(f'There is a total of {dcsync[0]["count(n)"]} objects with DCSync rights which are not Tier Zero')
    if dcsync[0]["count(n)"] > 0:
        print("Generating csv-file for: Affected Resources")
        q2 = "MATCH p=(n)-[:DCSync|AllExtendedRights|GenericAll]->(:Domain) WHERE NOT n.system_tags='admin_tier_0' RETURN n.name, n.objectid "
        dcsyncData, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
        writeCsvFile('dcsync.csv', dcsyncData)

def checkConstrainedDelegation(driver):
    printBanner('Checking Constrained Delegation')
    q = "MATCH (u:User)-[:AllowedToDelegate]->(c:Computer) WHERE (c.lastlogon > (datetime().epochseconds - (90 * 86400)) OR c.lastlogontimestamp > (datetime().epochseconds - (90 * 86400))) AND (u.lastlogon > (datetime().epochseconds - (90 * 86400)) OR u.lastlogontimestamp > (datetime().epochseconds - (90 * 86400))) RETURN count(DISTINCT u), count(DISTINCT c) "
    constrainedDelegation, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
    print(f'There are {constrainedDelegation[0]["count(DISTINCT u)"]} users allowed to delegate to {constrainedDelegation[0]["count(DISTINCT c)"]} computers')
    if constrainedDelegation[0]["count(DISTINCT u)"] > 0:
        q2 = "MATCH (u:User)-[:AllowedToDelegate]->(c:Computer) WHERE (c.lastlogon > (datetime().epochseconds - (90 * 86400)) OR c.lastlogontimestamp > (datetime().epochseconds - (90 * 86400))) AND (u.lastlogon > (datetime().epochseconds - (90 * 86400)) OR u.lastlogontimestamp > (datetime().epochseconds - (90 * 86400))) RETURN u.name, u.objectid, c.name, c.objectid "
        constrainedDelegationData, _, _ = driver.execute_query(q2, database_="neo4j", routing_=RoutingControl.READ)
        writeCsvFile('constrainedDelegation.csv', constrainedDelegationData)
        
def checkUnconstrainedDelegation(driver):
    printBanner('Checking Unconstrained Delegation')
    q = "MATCH (u) WHERE (u.unconstraineddelegation = true) AND (u.system_tags IS NULL) AND u.enabled = true AND (u.lastlogon > (datetime().epochseconds - (90 * 86400)) OR u.lastlogontimestamp > (datetime().epochseconds - (90 * 86400))) RETURN count(u) "
    unconstrainedDelegation, _, _ = driver.execute_query(q, database_="neo4j", routing_=RoutingControl.READ)
    print(f'There are {unconstrainedDelegation[0]["count(u)"]} non Tier Zero Objects allowed for unconstrained delegation.')
    if unconstrainedDelegation[0]["count(u)"] > 0:
        q2 = "MATCH (u) WHERE (u.unconstraineddelegation = true) AND (u.system_tags IS NULL) AND u.enabled = true AND (u.lastlogon > (datetime().epochseconds - (90 * 86400)) OR u.lastlogontimestamp > (datetime().epochseconds - (90 * 86400))) RETURN u.name, u.objectid "
        unconstrainedDelegationData, _, _ = driver.execute_query(q2, database_="neo4j", routing_=RoutingControl.READ)
        writeCsvFile('unconstrainedDelegation.csv', unconstrainedDelegationData)
        
def checkResourceBasedConstrainedDelegation(driver):
    printBanner('Checking Resource-based Constrained Delegation')
    resourcebasedConstrainedDelegation, _, _ = driver.execute_query(
        "MATCH p=(m)-[r:AllowedToAct]->(n) WHERE (m.system_tags IS NULL) RETURN count(m) ",
        database_="neo4j", routing_=RoutingControl.READ,
    )
    print(f'There are {resourcebasedConstrainedDelegation[0]["count(m)"]} non Tier Zero Object allowed for Resource-based Constrained Delegation.')
    if resourcebasedConstrainedDelegation[0]["count(m)"] > 0:
        q2 = "MATCH (u)-[r:AllowedToAct]->(n) WHERE (u.unconstraineddelegation = true) AND (u.system_tags IS NULL) AND u.enabled = true AND (u.lastlogon > (datetime().epochseconds - (90 * 86400)) OR u.lastlogontimestamp > (datetime().epochseconds - (90 * 86400))) RETURN u.name, u.objectid, n.name, n.objectid "
        resourcebasedConstrainedDelegationData, _, _ = driver.execute_query(q2, database_="neo4j", routing_=RoutingControl.READ)
        writeCsvFile('resourcebasedConstrainedDelegation.csv', resourcebasedConstrainedDelegationData)

def dumpDescriptions(driver):
    printBanner('Dumping Descriptions')
    descriptions, _, _ = driver.execute_query(
        "MATCH (n) "
        "WHERE n.description IS NOT NULL "
        "RETURN n.name, n.description ",
        database_="neo4j", routing_=RoutingControl.READ,
    )
    print(f'Dumping ALL descriptions for further manual analysis.')
    writeCsvFile('descriptions.csv', descriptions)

def collectBloodHoundNeo4j(apiInfo):
    with GraphDatabase.driver('neo4j://localhost:7687', auth=("neo4j", "bloodhoundcommunityedition")) as driver:
        basicInfos = collectBasicInfos(driver, apiInfo)
        genUserLists(driver)
        checkLaps(driver)
        checkUnsupportedOs(driver)
        checkInactiveUsersAndComputers(driver, basicInfos[0], basicInfos[1])
        checkKrbtgtPassword(driver)
        checkSensitiveAccountsAndProtectedUsers(driver)
        checkActiveGuest(driver)
        checkKerberoastableUsers(driver)
        checkAsrepRoasting(driver)
        checkTierZeroSessions(driver)
        checkConstrainedDelegation(driver)
        checkUnconstrainedDelegation(driver)
        checkResourceBasedConstrainedDelegation(driver)
        checkDcSync(driver)
        dumpDescriptions(driver)

def collectBloodHoundApi(dataDir):
    c = connectToApi()
    uploadData(c, dataDir)
    domains = getAvailableDomains(c)
    data = getDomainInfo(c, domains[0].id)
    return data

if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--data')
    args = parser.parse_args()

    apiData = collectBloodHoundApi(args.data)
    collectBloodHoundNeo4j(apiData)
