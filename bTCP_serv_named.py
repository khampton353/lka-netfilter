#!/usr/bin/env python
''' Python 3 version tcp server, receives data from client, writes
    as string to a file
'''

from socket import *
import time
import os


HOST = ''
PORT = 63001
BUFSIZ = 4096
ADDR = (HOST, PORT)
BANNER = '\n{:*^60}'    
SRVMSG='[{}] Server got {} bytes, lines so far:{}'
def do_serv():
    ''' simple TCP server that accepts a connection, receives data, saves
        it as a string to a file, and returns time-stamped status to the client
        Does user input and print IO
    '''
    print(BANNER.format(' TCP FILE RECEIVER '))
    tcpSerSock = socket(AF_INET, SOCK_STREAM)
    tcpSerSock.bind(ADDR)
    tcpSerSock.listen(5)
    #=int(input('Starting file number: '))
    
    while True:
        print('waiting for connection from Linux client on {} ...'.format(PORT))
        tcpCliSock, addr = tcpSerSock.accept()
        print('connected from: {}'.format(addr))
        name = tcpCliSock.recv(BUFSIZ)
        if not name:
            tcpCliSock.close()
            print('No Data')
            break
        name=name.decode('utf-8')
        print('name--',len(name),name)
        flno=0
        while True:
            try:
               f=open('{}{}'.format(name,flno if flno else ''),'r')
               f.close()
               flno +=1
            except FileNotFoundError:
                #good, file doesn't exist. not thread/process safe though
                f=open('{}{}'.format(name,flno if flno else ''),'wb')
                break
        tsz=cnt=0
        print('Receiving to ',f.name)
        tcpCliSock.send("ok".encode('utf-8')) #a little syncing here
        while True:
            data = tcpCliSock.recv(BUFSIZ)
            if not data:
                break
    
            f.write(data)
            sz=len(data)
            cnt+=data.decode('utf-8').count('\n')
            tsz+=sz
            tcpCliSock.send(
                SRVMSG.format(time.strftime(
                    '%X',time.localtime()), sz,cnt).encode('utf-8'))

        tcpCliSock.close()
        print("Wrote '{}' in {}, {} bytes, {} items".format(
            f.name,os.getcwd(),tsz,cnt))
        f.close()
    tcpSerSock.close()
    

if __name__ == '__main__':
    do_serv()


