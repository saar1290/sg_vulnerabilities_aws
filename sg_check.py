import json
import sys

js_name = input("Insert the path/name json file: ")

def read_file():
    try:
        with open(js_name) as f:
            global data
            data = json.load(f)
            check_securty_hole()
            f.close()
    except FileNotFoundError:
        print(js_name,"File not exist...")
        sys.exit(1)        
        

def check_securty_hole():
    f = open("/tmp/body.txt", 'w')
    any = "0.0.0.0/0"
    startbody = "Scanning all Security groups for open ports..."
    body = "--------------------------------------------"
    f.truncate()
    f.write(startbody+'\n')
    f.write(body+'\n')
    for i in data["SecurityGroups"]:
        ippermission = i["IpPermissions"]
        for p in ippermission:
            if "FromPort" in p:
                if p["FromPort"] != 443:
                    if p["IpProtocol"]:
                        for n in p["IpRanges"]:
                            if any == n["CidrIp"]:
                                wrn = str("Warning: found potentail security hole in "+i["GroupId"])
                                msg = "Inbound rule: Protocol "+ p["IpProtocol"] + " Port "+ str(p["FromPort"]) + " is open for CIDR" + n["CidrIp"] + " <---"
                                endbody = "--------------------------------------------"
                                f.write(wrn+'\n')
                                f.write(msg+'\n')
                                f.write(endbody+'\n')
    f.close()
read_file()