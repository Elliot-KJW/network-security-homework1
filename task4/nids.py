# Skeleton code for NIDS
import socket
import sys
import ipaddress
from scapy.all import *
from datetime import datetime
import re

protocol_dict = {1: 'icmp', 6: 'tcp', 17: 'udp'}
option_dict = {'tcp': ['seq', 'ack', 'window', 'flags'],
               'ip': ['id', 'tos', 'ttl'],
               'icmp': ['itype', 'icode']}


# You can utilize this class to parse the Snort rule and build a rule set.
class Rule:
    def __init__(self, action, protocol, src_ip, src_port, direction, dst_ip, dst_port, options, msg, original_rule):
        self.action = action
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_port = src_port
        self.direction = direction
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.options = options
        self.msg = msg

        self.original_rule = original_rule

    def __str__(self):
        return (f"action: {self.action}\n"
                f"protocol: {self.protocol}\n"
                f"src_ip: {self.src_ip}\n"
                f"src_port: {self.src_port}\n"
                f"direction: {self.direction}\n"
                f"dst_ip: {self.dst_ip}\n"
                f"dst_port: {self.dst_port}\n"
                f"options: {self.options}")


def parse_rule(line):
    # TODO: your code here
    line = line.strip()
    if not line or line.startswith('#'):  # 빈 줄 또는 주석인 경우 무시
        return None

    parse = line.split()
    action = parse[0]
    protocol = parse[1]
    src_ip = parse[2]
    src_port = parse[3]
    direction = parse[4]
    dst_ip = parse[5]
    dst_port = parse[6]
    option = line[line.find('(') + 1:len(line) - 1]
    options = {}
    for o in option.split(';')[:-1]:
        key, value = o.strip().split(':')
        if key.strip() == 'msg':
            msg = value.strip()

        options[key.strip()] = value.strip()

    return Rule(action, protocol, src_ip, src_port, direction, dst_ip, dst_port, options, msg, line)


def ip_validation(rule_ip, real_ip):
    if rule_ip == 'any':
        return True

    result = True

    if '[' in rule_ip:
        print('hi hello')
        p = re.compile(r'\[(.*?)\]')
        m = p.findall(rule_ip)
        for i in m[0].split(','):
            print(i)
            if ('!' in rule_ip and ipaddress.ip_address(real_ip) not in ipaddress.ip_network(i)) \
                    or ('!' not in rule_ip and ipaddress.ip_address(real_ip) in ipaddress.ip_network(i)):
                result = True
            else:
                result = False

    elif ipaddress.ip_address(real_ip) not in ipaddress.ip_network(rule_ip):
        if '!' in rule_ip:
            return True
        else:
            return False

    return result


def port_validation(rule_port, real_port):
    if rule_port != 'any':
        if ':' in rule_port:
            sBegin = int(rule_port.split(":")[0])
            sEnd = int(rule_port.split(":")[1])
            if real_port < sBegin or real_port > sEnd:
                return False
        elif str(real_port) not in rule_port.split(','):
            return False
    return True


def option_validation(packet, rule_protocol, rule_options):
    try:
        if rule_protocol != 'udp':
            for option in option_dict.get(rule_protocol):
                if rule_protocol == 'tcp' and (
                        rule_options.get(option) is not None and str(rule_options.get(option))
                        != str(eval('packet["TCP"].' + option))):
                    return False

                if rule_protocol == 'icmp' and (
                        rule_options.get(option) is not None and str(rule_options.get(option))
                        != str(eval('packet["ICMP"].' + option[1:]))):
                    return False

        for option in option_dict.get('ip'):
            if (rule_options.get(option) is not None and str(rule_options.get(option))
                    != str(eval('packet["IP"].' + option))):
                return False

        if rule_options.get("content") is not None:
            payload_data = str(raw(packet).decode('unicode_escape'))
            if (str(rule_options.get("content")) not in str(packet.payload)
                    and str(rule_options.get("content")).replace('"', '') not in payload_data):
                return False
    except:
        print(traceback.format_exc())

    return True


def parse_packet(packet, rule_set):
    # TODO: your code here
    ip = packet.payload
    for rule in rule_set:
        if protocol_dict[ip.proto] == rule.protocol:
            # ip and port and option validation
            match = (ip_validation(rule.src_ip, ip.src)
                     and ip_validation(rule.dst_ip, ip.dst)
                     and option_validation(packet, rule.protocol, rule.options))

            if rule.protocol in ('tcp', 'udp'):
                match = (match and port_validation(rule.src_port, ip.sport)
                         and port_validation(rule.dst_port, ip.dport))

            if match:
                if rule.protocol in ('tcp', 'udp'):
                    print(str(datetime.now().strftime("%Y/%m/%d %H:%M:%S")) + " "
                          + rule.msg + " "
                          + rule.protocol + " " + ip.src + " " + str(ip.sport) + " "
                          + rule.direction + " " + ip.dst + " " + str(ip.dport)
                          )
                if rule.protocol == 'icmp':
                    print(str(datetime.now().strftime("%Y/%m/%d %H:%M:%S")) + " "
                          + rule.msg + " "
                          + rule.protocol + " " + ip.src + " "
                          + rule.direction + " " + ip.dst + " "
                          )

                print('options:')
                for option, value in rule.options.items():
                    print(" " + f"{option}: {value}")
                print("\n")


if __name__ == '__main__':
    rule_file = sys.argv[1]

    f = open(rule_file, 'r')

    rule_set = []
    lines = f.readlines()
    for line in lines:
        rule = parse_rule(line)
        rule_set.append(rule)

    print("Start sniffing")
    sniff(iface='eth0', prn=lambda p: parse_packet(p, rule_set), filter='ip')

    f.close()
