from scapy.all import *
import re
import base64

NUM_ALERT = 0
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


def readpcap(fileName):
    return rdpcap(fileName)


def isFinScan(tcp_packet):
    return tcp_packet.flags == FIN


def isNullScan(tcp_packet):
    return tcp_packet.flags == 0


def isXmasScan(tcp_packet):
    return tcp_packet.flags == (FIN | URG | PSH)


def isNiktoScan(pkt):
    if pkt.haslayer(Raw):
        raw = pkt[Raw].load
        if "Nikto" in raw:
            return True
    return False


def hasPassword(packet):
    hasPassword = False
    username, password, userPass, port = '', '', '', ''
    # HTTP request
    if (packet.haslayer(Raw)):
        rawTxt = packet.getlayer(Raw).load
        # Find username and pass in HTTP forms
        username = re.findall(r"(?i)use?r(?:name)?[=|:|\s]([^\&]*)[\&|\r]", rawTxt)
        password = re.findall(r"(?i)pass(?:word)?[=|:|\s]([^\&]*)[\&|\r]", rawTxt)
        # Find Basic Authentication
        basic = re.findall(r"(?i)Authorization: Basic ([^\r]*)", rawTxt)
        login = re.findall(r"(?i)Login ([^\s]*) ([^\r]*)\r", rawTxt)
        # print login
        if (len(basic)):
            userPass = base64.b64decode(basic[0])
            port = packet[IP].dport
            hasPassword = True
        elif (len(login)):
            userPass = login[0][0] + ":" + login[0][1]
            port = packet[IP].dport
            hasPassword = True
        elif (len(username) + len(password) != 0):
            hasPassword = True
            port = packet[IP].dport
            if (len(username) == 0):
                userPass = ":" + password.pop()
            elif (len(password) == 0):
                userPass = username.pop() + ":"
            else:
                userPass = username.pop() + ":" + password.pop()
        else:
            userPass = ''

        return hasPassword, userPass, port
    else:
        return hasPassword, userPass, port


def displayScanAlert(packet, protocol, alertType, alertNum):
    print
    "ALERT #{0}: {1} is detected from {2} ({3})!".format(alertNum, alertType, packet[IP].src, protocol)


def displayPasswordAlert(packet, protocol, alertNum, payload):
    print
    "ALERT #{0}: Username and password sent in-the-clear from {1} ({2}) ({3})!".format(alertNum, packet[IP].src,
                                                                                       protocol, payload)


def scanPackets(filename):
    packets = rdpcap(filename)
    for pkt in packets:
        analyzePacket(pkt)
    return


def analyzePacket(pkt):
    global NUM_ALERT
    if pkt.haslayer(TCP):
        NUM_ALERT += 1
        if (isFinScan(pkt.getlayer(TCP))):
            displayScanAlert(pkt, 'TCP', 'FIN scan', NUM_ALERT)
        elif (isNullScan(pkt.getlayer(TCP))):
            displayScanAlert(pkt, 'TCP', 'NULL scan', NUM_ALERT)
        elif (isXmasScan(pkt.getlayer(TCP))):
            displayScanAlert(pkt, 'TCP', 'XMAS scan', NUM_ALERT)
        elif (isNiktoScan(pkt)):
            displayScanAlert(pkt, 'HTTP', 'Nikto scan', NUM_ALERT)
        elif (hasPassword(pkt)[0]):
            isPassword, userPass, port = hasPassword(pkt)
            displayPasswordAlert(pkt, port, NUM_ALERT, userPass)
        else:
            NUM_ALERT -= 1
    return


def checkArgument():
    if len(sys.argv) == 2:
        if sys.argv[1] != "-h":
            printUsage()
            sys.exit()
    elif len(sys.argv) == 3:
        if ((sys.argv[1] != "-r") and (sys.argv[1] != "-i")):
            printUsage()
            sys.exit()
    else:
        printUsage()
    return


def printUsage():
    print
    "usage: alarm.py [-h] [-i INTERFACE] [-r PCAPFILE] \n\nA network sniffer that identifies basic vulnerabilities " \
    "\n\noptional arguments:\n\t-h, --help    show this help message and exit\n\t-i INTERFACE  Network interface to " \
    "sniff on\n\t-r PCAPFILE   A PCAP file to read"
    sys.exit()
    return


def sniffNetwork(interface):
    sniff(interface, prn=analyzePacket)
    return


def run():
    if len(sys.argv) == 1:
        sniffNetwork('eth0')
    else:
        checkArgument()
        mode = sys.argv[1]
        print
        mode
        if mode == '-i':
            ether = sys.argv[2]
            sniffNetwork(ether)
        if mode == '-r':
            filename = sys.argv[2]
            scanPackets(filename)
    return


if __name__ == '__main__':
    run()
