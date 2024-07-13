from twisted.internet import protocol, reactor
from  ipaddress import IPv4Address, IPv4Network
import time
import io, os
from twisted.logger import jsonFileLogObserver, Logger
import argparse
import configparser

ServerPort = 8080
AllowedIPRanges = []
IsACtiveMode = False
LogFileName = "honey-server.json"

def write_syslog(logger, type_,message_):
    if type_ == "alert":
        pass

    if type_ == 'debug':
        pass 

def isClientIpAllowed(self,ip_):
    for ip in AllowedIPRanges:
        if (isinstance(ip,IPv4Address) and IPv4Address(ip_) == ip) or (isinstance(ip,IPv4Network) and IPv4Address(ip_) in ip):
            self.log.debug(f"IP {ip_} in allowed IP ranges")
            self.transport.write(b"This is HoneyPort server!")
            self.transport.loseConnection()
            return True
        else:
            return False

def blockClientIpAddress(self, ip_):
    self.log.debug(f"Taking action to block {ip_}")
    # TODO check the IP tables, for existing Deny rules or allow rules
    # TODO add the IP address in the deny rule and drop the connection.
    # TODO log the above steps,
    self.transport.loseConnection()

    

class TCPServerImpl(protocol.Protocol):
    def __init__(self):
        self.log = Logger(observer=jsonFileLogObserver(io.open(LogFileName, "a")),
             namespace="saver") 

        self.log.info("Staring the Honey-pyHole Server..")

    def connectionMade(self):
        # after tcp handshake commpleted
        client_ip = self.transport.getHost().host
        
        self.log.debug(f"Connection received from {client_ip}.")
        
        if isClientIpAllowed(self, client_ip):
            self.log.debug(f"Connection is received from allowed IP/IP Ranges: {client_ip}")
        else:
            self.log.alert(f"Connection is received from Unknown IP/IP Ranges: {client_ip}")
            if IsACtiveMode:
                blockClientIpAddress(self, client_ip)
            else:
                time.sleep(3) #-> till the scapy is started
                # TODO start the scapy sniffer, uppon connection close we also need to close the capture
                    # TODO check the permission


    def dataReceived(self, data):
        "As soon as any data is received, the following things"
        self.transport.write(data)

        self.log.debug(f"Received {len(data)} bytes data from {self.transport.getHost().host}")
        self.log.debug(f"DATA: {str(data)}")
        # TODO Write the data into a packet catpure, for further analysis -> 
            # this is in application layer, after completing the tcp handshake we can see the data, 
            # So we can only get the data forwarded from the client, (above tcp later), 
            #if we want to stor the capture we need to use something like sniffer

def print_stats(ServerPort, IsACtiveMode, LogFileName, AllowedIPRanges):
    print("-"*80)
    print(f"Server Port: {ServerPort}\nIs Active Mode: {IsACtiveMode}\nLog File Name: {LogFileName}\nAllowed Ip Address/Networks: {AllowedIPRanges}")
    print("-"*80)

def main():  

    parser = argparse.ArgumentParser(
                      prog='Honey-PyHole',
                      description="Run the service on the given port and wait for any TCP connections on it, if the client connected is in the allowed range of IPs, It will log and allow the the connection by forwarding it towards the requested port,  Add clients unknown IPs in the IP table for traffic filtering")
    
    parser.add_argument('-c' ,'--config-file', action="store", default="honey-server.ini", help="Configuration file to read for basic params")
    args = vars(parser.parse_args())
    config_file_name = args['config_file']
    
    if not os.path.isfile(config_file_name):
        print(f"Given configuration file or default configuration file not availeble/Program doesn't have a permission to read the file {config_file_name}")
        exit(0)
    else:
        print(f"Reading configuration file.. {config_file_name}")

    config = configparser.ConfigParser()
    config.read(config_file_name)
    
    if "ServerSettings" not in config.sections():
        print("Not able to parse the config file/Expected options not available, Refer template for configuring custom options")
        exit(0)
    if "port" in config["ServerSettings"]:
        ServerPort = int(config["ServerSettings"]["port"])
    else:
        print(f"Not able to parse the port from the configuration file, Hence using the default port {ServerPort}")

    if "mode" in config["ServerSettings"]:
        if config['ServerSettings']["mode"] == "PASSIVE":
            IsACtiveMode = False
        else:
            IsACtiveMode = True
    else:
        print(f"Not able to parse the Mode from the configuration file, Hence using the default mode {IsACtiveMode}")

    if "logfilename" in config["ServerSettings"]:
        LogFileName = config['ServerSettings']['logfilename']
    else:
        print(f"Not able to parse the log file name from the configuration file, Hence using the default log file name {LogFileName}")

    if "allowedipranges" in config["ServerSettings"]:
        temp = config["ServerSettings"]["allowedipranges"]
        ipsAndIpRanges = [ip.strip() for ip in temp.split(",")]

        for ip in ipsAndIpRanges:
            if '/' in ip:
                AllowedIPRanges.append(IPv4Network(ip))
            else:
                AllowedIPRanges.append(IPv4Address(ip))

    print_stats(ServerPort, IsACtiveMode, LogFileName, AllowedIPRanges)

    factory = protocol.ServerFactory()
    factory.protocol = TCPServerImpl
    reactor.listenTCP(ServerPort, factory)
    reactor.run()

if __name__ == "__main__":
    main()
