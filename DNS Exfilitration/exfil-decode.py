from scapy.all import *
import sys
import re
import pandas as pd
from optparse import OptionParser
import base64
from scipy.stats import *


sys.tracebacklimit = None

data={"SRC": [], "DST": [], "DOMAIN": [], "TYPE": [], "DECODED_STRING": []}

# UDP_FULL_DUPLEX was taken from https://gist.github.com/sdcampbell/2b62a22c4378639161c9bc5ce0d3dbc4 
def udp_full_duplex(p):
    sess = "Other"
    if 'UDP' in p:
        sess = str(sorted(["UDP", p[IP].src, p[UDP].sport, p[IP].dst, p[UDP].dport], key=str))
    return sess

def Entropy(domain):
    entro=0.0
    pr, lns=collections.Counter(
                    str(domain, 'latin-1')), float(len(str(domain, 'latin-1')))
    return entropy([k/lns for k in pr.values()], None, 2)

def DNdecode(dns):
    decoded = ''

    if re.compile("[0-9a-f]{30,63}").match(dns) :
        parsed = re.compile("[0-9a-o]{30,63}").findall(dns)
        string = ''.join(parsed)
        decoded = bytes.fromhex(string).decode('latin-1')
    elif re.compile("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"):
        parsed = re.compile("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?").findall(dns)
        topdomain = [base64.b64decode(bytes(item, 'latin-1')).decode('latin-1') if item != '' else '' for item in parsed]
        decoded = ' '.join(topdomain)
    elif re.compile("(?:[A-Z2-7+/]{4})*(?:[A-Z2-7+/]{2}==|[A-Z2-7+/]{3}=)?"):
        parsed = re.compile("(?:[A-Z2-7+/]{4})*(?:[A-Z2-7+/]{2}==|[A-Z2-7+/]{3}=)?").findall(dns)
        topdomain = [base64.b32decode(bytes(item, 'latin-1')).decode('latin-1') if item != '' else '' for item in parsed]
        decoded = ''.join(topdomain)
    else:
        decoded = 'Unable to decode the data'

    return decoded

def DetectDecode(pcapfile):
    packets = sniff(offline=pcapfile, lfilter = lambda s: "DNS" in s)
    for key, value in packets.sessions(udp_full_duplex).items():
        header = [item.strip('\'') for item in key.strip('][').split(', ')]
        data["SRC"].append(header[0])
        data["DST"].append(header[1])
        for p in value:
            if p["DNS"].qr == 1 and p["DNS"].ancount != 0:
                if Entropy(p["DNS"].an.rrname) > 2.5:
                    data["DOMAIN"].append(p["DNS"].an.rrname.decode('latin-1'))
                    data["TYPE"].append(p["DNS"].an.type)
                    data["DECODED_STRING"].append(DNdecode(p["DNS"].an.rrname.decode('latin-1')))

    return data



if __name__ == '__main__':
    try:
        parser = OptionParser(
        usage="%s [options]\n" % sys.argv[0] )
        parser.add_option("-p", "--pcap", dest="pcapfile", type="string", help="the pcap file that you want to parse")
        parser.add_option("-o", "--out", dest="out", type="string", help="output file")
        (options, args) = parser.parse_args()

        if options.pcapfile == None:
            parser.print_help()
            sys.exit(1)
        try:
            data = DetectDecode(options.pcapfile)
            df   = pd.DataFrame(data)
            if options.out!=None and options.out.split(".")[len(options.out.split(".")) -1] == "csv":
                df.to_csv(options.out)
            else:
                print(df)
        except :
            print("Something wrong with the PCAP file %s" % options.pcapfile)
            print(data)
            sys.exit(1)

    except KeyboardInterrupt:
        print("Interrupting the process.....")
        try:
            print("Process interrupted by the user")
            sys.exit(0)
        except SystemExit:
            print("Process interrupted by the kernel")
            os._exit(0)
