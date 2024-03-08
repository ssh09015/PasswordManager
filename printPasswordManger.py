# 크롬, 엣지 브라우저 해킹 통합

#printPasswordManager.py
import os

# 필요 패키지 설치
os.system('python.exe -m pip install --upgrade pip')
os.system('pip install pycryptodomex')
os.system('pip install pypiwin32')
exec(open("decryptChrome.py","rt",encoding='UTF8').read())
exec(open("decryptEdge.py","rt",encoding='UTF8').read())
# exec(open("decryptChrome.py").read()) #UnicodeDecodeError: 'cp949' codec can't decode byte 0xed in position 1: illegal multibyte sequence 이러한 에러가 나서 위와 같이 encoding추가했다.
# exec(open("decryptEdge.py").read())