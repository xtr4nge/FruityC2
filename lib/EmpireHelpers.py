'''
This functions have been copied from Empire
Site: http://www.powershellempire.com/
GitHub: https://github.com/adaptivethreat/Empire/blob/master/lib/common/helpers.py

Misc. helper functions used in Empire.
'''
import re

def uniquify_tuples(tuples):
    # uniquify mimikatz tuples based on the password
    # cred format- (credType, domain, username, password, hostname, sid)
    seen = set()
    return [item for item in tuples if "%s%s%s%s"%(item[0],item[1],item[2],item[3]) not in seen and not seen.add("%s%s%s%s"%(item[0],item[1],item[2],item[3]))]

def validate_ntlm(data):

    allowed = re.compile("^[0-9a-f]{32}", re.IGNORECASE)
    if allowed.match(data):
        return True
    else:
        return False

def parse_mimikatz(data):
    """
    Parse the output from Invoke-Mimikatz to return credential sets.
    """

    # cred format:
    #   credType, domain, username, password, hostname, sid
    creds = []

    # regexes for "sekurlsa::logonpasswords" Mimikatz output
    regexes = ["(?s)(?<=msv :).*?(?=tspkg :)", "(?s)(?<=tspkg :).*?(?=wdigest :)", "(?s)(?<=wdigest :).*?(?=kerberos :)", "(?s)(?<=kerberos :).*?(?=ssp :)", "(?s)(?<=ssp :).*?(?=credman :)", "(?s)(?<=credman :).*?(?=Authentication Id :)", "(?s)(?<=credman :).*?(?=mimikatz)"]

    hostDomain = ""
    domainSid = ""
    hostName = ""

    lines = data.split("\n")

    for line in lines[0:2]:
        if line.startswith("Hostname:"):
            try:
                domain = line.split(":")[1].strip()
                temp = domain.split("/")[0].strip()
                domainSid = domain.split("/")[1].strip()

                hostName = temp.split(".")[0]
                hostDomain = ".".join(temp.split(".")[1:])
            except:
                pass

    for regex in regexes:

        p = re.compile(regex)

        for match in p.findall(data):

            lines2 = match.split("\n")
            username, domain, password = "", "", ""
            
            for line in lines2:
                try:
                    if "Username" in line:
                        username = line.split(":",1)[1].strip()
                    elif "Domain" in line:
                        domain = line.split(":",1)[1].strip()
                    elif "NTLM" in line or "Password" in line:
                        password = line.split(":",1)[1].strip()
                except:
                    pass

            if username != "" and password != "" and password != "(null)":
                
                sid = ""

                # substitute the FQDN in if it matches
                if hostDomain.startswith(domain.lower()):
                    domain = hostDomain
                    sid = domainSid

                if validate_ntlm(password):
                    credType = "hash"

                else:
                    credType = "plaintext"

                # ignore machine account plaintexts
                if not (credType == "plaintext" and username.endswith("$")):
                    creds.append((credType, domain, username, password, hostName, sid))

    if len(creds) == 0:
        # check if we have lsadump output to check for krbtgt
        #   happens on domain controller hashdumps
        for x in xrange(8,13):
            if lines[x].startswith("Domain :"):

                domain, sid, krbtgtHash = "", "", ""

                try:
                    domainParts = lines[x].split(":")[1]
                    domain = domainParts.split("/")[0].strip()
                    sid = domainParts.split("/")[1].strip()

                    # substitute the FQDN in if it matches
                    if hostDomain.startswith(domain.lower()):
                        domain = hostDomain
                        sid = domainSid

                    for x in xrange(0, len(lines)):
                        if lines[x].startswith("User : krbtgt"):
                            krbtgtHash = lines[x+2].split(":")[1].strip()
                            break

                    if krbtgtHash != "":
                        creds.append(("hash", domain, "krbtgt", krbtgtHash, hostName, sid))
                except Exception as e:
                    pass

    if len(creds) == 0:
        # check if we get lsadump::dcsync output
        if '** SAM ACCOUNT **' in lines:
            domain, user, userHash, dcName, sid = "", "", "", "", ""
            for line in lines:
                try:
                    if line.strip().endswith("will be the domain"):
                        domain = line.split("'")[1]
                    elif line.strip().endswith("will be the DC server"):
                        dcName = line.split("'")[1].split(".")[0]
                    elif line.strip().startswith("SAM Username"):
                        user = line.split(":")[1].strip()
                    elif line.strip().startswith("Object Security ID"):
                        parts = line.split(":")[1].strip().split("-")
                        sid = "-".join(parts[0:-1])
                    elif line.strip().startswith("Hash NTLM:"):
                        userHash = line.split(":")[1].strip()
                except:
                    pass

            if domain != "" and userHash != "":
                creds.append(("hash", domain, user, userHash, dcName, sid))

    return uniquify_tuples(creds)

def strip_powershell_comments(data):
    """
    Strip block comments, line comments, empty lines, verbose statements,
    and debug statements from a PowerShell source file.
    """
    
    # strip block comments
    strippedCode = re.sub(re.compile('<#.*?#>', re.DOTALL), '', data)

    # strip blank lines, lines starting with #, and verbose/debug statements
    strippedCode = "\n".join([line for line in strippedCode.split('\n') if ((line.strip() != '') and (not line.strip().startswith("#")) and (not line.strip().lower().startswith("write-verbose ")) and (not line.strip().lower().startswith("write-debug ")) )])
    
    return strippedCode
