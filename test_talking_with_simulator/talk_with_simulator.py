# encoding:utf-8
import sys
import socket
from socket import socket, AF_INET, SOCK_STREAM


def main():
    sys.stdout.write('start\n')
    talk_with_simulator()
    sys.stdout.write('end\n')


def talk_with_simulator():
    """Simulator 通讯测试
    """

    platformSock = socket(AF_INET, SOCK_STREAM)
    platformSock.connect(('127.0.0.1', 2322))

    platformSock.send('\0\0\0\1')

    tpmSock = socket(AF_INET, SOCK_STREAM)
    tpmSock.connect(('127.0.0.1', 2321))

    # Send TPM_SEND_COMMAND
    tpmSock.send('\x00\x00\x00\x08')
    # Send locality
    tpmSock.send('\x03')
    # Send # of bytes
    tpmSock.send('\x00\x00\x00\x0c')
    # Send tag
    tpmSock.send('\x80\x01')
    # Send command size
    tpmSock.send('\x00\x00\x00\x0c')
    # Send command code: TPMStartup
    tpmSock.send('\x00\x00\x01\x44')
    # Send TPM SU
    tpmSock.send('\x00\x00')

    # Receive 4 bytes of 0's
    response = tpmSock.recv(18)
    display_data(response, 4)
    return


def display_data(data, length):
    """检查 TPM Simulator 返回的数据

    :param response: Socket 套接字返回的数据
    """
    for i in range(length):
        ch = data[i]
        print("data[%d]=0x%02x" % (i, ord(ch)))
    pass



if '__main__' == __name__:
    main()
