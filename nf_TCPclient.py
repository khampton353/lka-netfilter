#!/usr/bin/env python
'''test netfilter driver by sending/receiving a small file'''

from socket import *
import os
HOST = '10.0.0.110'
PORT = 63001
BUFSIZ = 1024
ADDR = (HOST, PORT)
BANNER = '\n{:*^60}'

def do_client(fname):
    ''' VERY simple TCP client used to get a file from a Linux system to a
        Windows system running a TCP server
    '''
    tcpCliSock = socket(AF_INET, SOCK_STREAM)
    tcpCliSock.connect(ADDR)
    cnt=tsz=sz=0
    tcpCliSock.send(fname.split(os.sep)[-1].encode())
    #tcpCliSock.send('\n'.encode())
    data=tcpCliSock.recv(BUFSIZ)
    yield "{} {}\n".format(data.decode()[:2],len(data))
    yield "Sending file: {}\n".format(fname)                
    with open(fname,'rb') as f:
        yield "transmitting file '{}'".format(f.name)
        while True:
            r=f.read()
            if not r:
                break
            cnt+=1
            sz=len(r)
            tsz += sz
            yield '\nsending line {}, sz: {} --- rcvd: '.format(cnt,sz)
            tcpCliSock.send(r)
            data = tcpCliSock.recv(BUFSIZ)
            if not data:
                break
            yield data.decode()
        yield "\nSent {} line(s), {} total bytes\n".format(cnt,tsz)

    tcpCliSock.close()


if __name__ == '__main__':
    def run_client():
        '''simple routine that gets a file name and uses a tcp socket to
           send a file line by line
        '''
        print(BANNER.format(' TCP CLIENT '))
        #fn=input("file to send? ")
        fn="/home/khampton/pytest.fil"
        for ln in do_client(fn):
            print(ln, end='')
        
    run_client()

