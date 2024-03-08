#무차별 공격

import sys
import os
import struct
from binascii import hexlify

def process_2x_database(data, databaseName):

    index = 12
    endReached = False
    masterSeed = ''
    transformSeed = ''
    transformRounds = 0
    initializationVectors = ''
    expectedStartBytes = ''
    

    while endReached == False:
        btFieldID = struct.unpack("B", data[index:index+1])[0] 
        #btFieldID = struct.unpack("B", data[index])[0] # B : 부호 없는 정수(바이트 수 1) 
        index += 1

        uSize = struct.unpack("H", data[index:index+2])[0] # H : 부호 없는 정수(바이트 수 2)
        index += 2
        #print("btFieldID : %s , uSize : %s" %(btFieldID, uSize))
        
        if btFieldID == 0:
            endReached = True

        if btFieldID == 4:
            #masterSeed = hexlify(data[index:index+uSize])
            masterSeed = data[index:index+uSize].hex()

        if btFieldID == 5:
            transformSeed = hexlify(data[index:index+uSize])

        if btFieldID == 6:
            transformRounds = struct.unpack("H", data[index:index+2])[0]

        if btFieldID == 7:
            initializationVectors = hexlify(data[index:index+uSize])

        if btFieldID == 9:
            expectedStartBytes = hexlify(data[index:index+uSize])

        index += uSize

    dataStartOffset = index
    firstEncryptedBytes = hexlify(data[index:index+32])

    #dataStartOffset까진 같다.
    return "%s:$keepass$*2*%s*%s*%s*%s*%s*%s*%s" %(databaseName, transformRounds, dataStartOffset, masterSeed, transformSeed, initializationVectors, expectedStartBytes, firstEncryptedBytes)


def process_database(filename):

    f = open(filename, 'rb')
    data = f.read() #Database.kdbx를 읽어들임
    f.close()

    base = os.path.basename(filename) #Database.kdbx
    databaseName = os.path.splitext(base)[0] #Database

    fileSignature = data[0:8].hex() # fileSignature = hexlify(data[0:8]) 주어진 인수의 16진수 값을 반환 
    #여기서 인수는 16진수로 변환할 바이트 변수(data[0:8])이다.

    if(fileSignature == '03d9a29a67fb4bb5'):
        # "2.X"
        print(process_2x_database(data, databaseName))

    elif(fileSignature == '03d9a29a66fb4bb5'):
        # "2.X pre release"
        print(process_2x_database(data, databaseName))

    else:
        print("ERROR: KeePass signaure unrecognized")


if __name__ == "__main__":
    if len(sys.argv) < 2: # python keepass2john.py Database.kdbx로 인자 3개니까 이 if문은 건너 뜀
        sys.stderr.write("Usage: %s <kdb[x] file[s]>\n" % sys.argv[0]) 
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_database(sys.argv[i]) # 여기까진 들어감
