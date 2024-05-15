import socket
import sys


def port_scanner(target_ip, start_portno, end_portno):
    for port_number in range(start_portno, end_portno):
        # TODO: your code here
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, port_number))
            print(port_number, "is opened")
            s.close()
        except ConnectionRefusedError:
            continue
        except TimeoutError:
            continue


if __name__ == '__main__':
    target_ip = sys.argv[1]
    start_portno = int(sys.argv[2])
    end_portno = int(sys.argv[3])

    port_scanner(target_ip, start_portno, end_portno)
