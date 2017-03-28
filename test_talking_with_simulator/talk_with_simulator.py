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

    platformSock.send(b'\x00\x00\x00\x01')

    tpmSock = socket(AF_INET, SOCK_STREAM)
    tpmSock.connect(('127.0.0.1', 2321))

    # Send TPM_SEND_COMMAND
    tpmSock.send(b'\x00\x00\x00\x08')
    # Send locality
    tpmSock.send(b'\x03')
    # Send # of bytes
    tpmSock.send(b'\x00\x00\x00\x0c')
    # Send tag
    tpmSock.send(b'\x80\x01')
    # Send command size
    tpmSock.send(b'\x00\x00\x00\x0c')
    # Send command code: TPMStartup
    tpmSock.send(b'\x00\x00\x01\x44')
    # Send TPM SU
    tpmSock.send(b'\x00\x00')

    # Receive response size from Simulator.exe
    n = uint32_from_raw(tpmSock.recv(4))
    # Receive TPM 2.0 response data
    data = tpmSock.recv(n)
    print("data = %s" % string_from_raw(data, n))
    class response:
        tag = data[:2]
        size = uint32_from_raw(data[2:6])
        code = data[6:]
    print("response.tag = 0x%s" % string_from_raw(response.tag, 2))
    print("response.size = %d Bytes" % response.size)
    print("response.code = 0x%s" % string_from_raw(response.code, 4))
    return


def uint_from_raw(raw_data):
    """将原始二进制数据转换为无符号整数

    :param raw_data: 原始数据
    :return:
    """
    result = 0
    for i in raw_data:
        result = (result << 8) + i
    return result


def uint16_from_raw(raw_data):
    """将原始二进制数据转换为 uint16_t 无符号整数

    :param raw_data: 原始数据
    :return:
    """
    if len(raw_data) < 2:
        raise ValueError('原始数据长度不足2字节无法转换为16位数据')
    return uint_from_raw(raw_data[:2])


def uint32_from_raw(raw_data):
    """将原始二进制数据转换为 uint32_t 无符号整数

    :param raw_data: 原始数据
    :return:
    """
    if len(raw_data) < 4:
        raise ValueError('原始数据长度不足4字节无法转换为32位数据')
    return uint_from_raw(raw_data[:4])


def string_from_raw(raw_data, length):
    """检查 TPM Simulator 返回的数据

    :param raw_data: 必须是 b'' 二进制数据串
    :param length: 必须是正整数
    """
    n = len(raw_data)
    if n > length and length > 0:
        n = length
    val = ''
    for i in raw_data[:n]:
        s = "%02X" % (i)
        val = ''.join((val, s))
    return val


if '__main__' == __name__:
    main()
