'''coding:UTF-8'''
# 导入字典
ascii_two_positive = {' ':'0010 0000','!':'0010 0001','"':'0010 0010','#':'0010 0011','$':'0010 0100','%':'0010 0101','&':'0010 0110',"'":'0010 0111','(':'0010 1000',')':'0010 1001','*':'0010 1010','+':'0010 1011',',':'0010 1100','-':'0010 1101','.':'0010 1110','/':'0010 1111','0':'0011 0000','1':'0011 0001','2':'0011 0010','3':'0011 0011','4':'0011 0100','5':'0011 0101','6':'0011 0110','7':'0011 0111','8':'0011 1000','9':'0011 1001',':':'0011 1010',';':'0011 1011','<':'0011 1100','=':'0011 1101','>':'0011 1110','?':'0011 1111','@':'0100 0000','A':'0100 0001','B':'0100 0010','C':'0100 0011','D':'0100 0100','E':'0100 0101','F':'0100 0110','G':'0100 0111','H':'0100 1000','I':'0100 1001','J':'0100 1010','K':'0100 1011','L':'0100 1100','M':'0100 1101','N':'0100 1110','O':'0100 1111','P':'0101 0000','Q':'0101 0001','R':'0101 0010','S':'0101 0011','T':'0101 0100','U':'0101 0101','V':'0101 0110','W':'0101 0111','X':'0101 1000','Y':'0101 1001','Z':'0101 1010','[':'0101 1011','\\':'0101 1100',']':'0101 1101','^':'0101 1110','_':'0101 1111','`':'0110 0000','a':'0110 0001','b':'0110 0010','c':'0110 0011','d':'0110 0100','e':'0110 0101','f':'0110 0110','g':'0110 0111','h':'0110 1000','i':'0110 1001','j':'0110 1010','k':'0110 1011','l':'0110 1100','m':'0110 1101','n':'0110 1110','o':'0110 1111','p':'0111 0000','q':'0111 0001','r':'0111 0010','s':'0111 0011','t':'0111 0100','u':'0111 0101','v':'0111 0110','w':'0111 0111','x':'0111 1000','y':'0111 1001','z':'0111 1010','{':'0111 1011','|':'0111 1100','}':'0111 1101','~':'0111 1110'}
ascii_ten_positive = {' ':'32','!':'33','"':'34','#':'35','$':'36','%':'37','&':'38',"'":'39','(':'40',')':'41','*':'42','+':'43',',':'44','-':'45','.':'46','/':'47','0':'48','1':'49','2':'50','3':'51','4':'52','5':'53','6':'54','7':'55','8':'56','9':'57',':':'58',';':'59','<':'60','=':'61','>':'62','?':'63','@':'64','A':'65','B':'66','C':'67','D':'68','E':'69','F':'70','G':'71','H':'72','I':'73','J':'74','K':'75','L':'76','M':'77','N':'78','O':'79','P':'80','Q':'81','R':'82','S':'83','T':'84','U':'85','V':'86','W':'87','X':'88','Y':'89','Z':'90','[':'91','\\':'92',']':'93','^':'94','_':'95','`':'96','a':'97','b':'98','c':'99','d':'100','e':'101','f':'102','g':'103','h':'104','i':'105','j':'106','k':'107','l':'108','m':'109','n':'110','o':'111','p':'112','q':'113','r':'114','s':'115','t':'116','u':'117','v':'118','w':'119','x':'120','y':'121','z':'122','{':'123','|':'124','}':'125','~':'126'}
ascii_sixteen_positive = {' ':'20','!':'21','"':'22','#':'23','$':'24','%':'25','&':'26',"'":'27','(':'28',')':'29','*':'2a','+':'2b',',':'2c','-':'2d','.':'2e','/':'2f','0':'30','1':'31','2':'32','3':'33','4':'34','5':'35','6':'36','7':'37','8':'38','9':'39',':':'3a',';':'3b','<':'3c','=':'3d','>':'3e','?':'3f','@':'40','A':'41','B':'42','C':'43','D':'44','E':'45','F':'46','G':'47','H':'48','I':'49','J':'4a','K':'4b','L':'4c','M':'4d','N':'4e','O':'4f','P':'50','Q':'51','R':'52','S':'53','T':'54','U':'55','V':'56','W':'57','X':'58','Y':'59','Z':'5a','[':'5b','\\':'5c',']':'5d','^':'5e','_':'5f','`':'60','a':'61','b':'62','c':'63','d':'64','e':'65','f':'66','g':'67','h':'68','i':'69','j':'6a','k':'6b','l':'6c','m':'6d','n':'6e','o':'6f','p':'70','q':'71','r':'72','s':'73','t':'74','u':'75','v':'76','w':'77','x':'78','y':'79','z':'7a','{':'7b','|':'7c','}':'7d','~':'7e'}
ascii_two_reverse = {'0010 0000':' ','0010 0001':'!','0010 0010':'"','0010 0011':'#','0010 0100':'$','0010 0101':'%','0010 0110':'&','0010 0111':"'",'0010 1000':'(','0010 1001':')','0010 1010':'*','0010 1011':'+','0010 1100':',','0010 1101':'-','0010 1110':'.','0010 1111':'/','0011 0000':'0','0011 0001':'1','0011 0010':'2','0011 0011':'3','0011 0100':'4','0011 0101':'5','0011 0110':'6','0011 0111':'7','0011 1000':'8','0011 1001':'9','0011 1010':':','0011 1011':';','0011 1100':'<','0011 1101':'=','0011 1110':'>','0011 1111':'?','0100 0000':'@','0100 0001':'A','0100 0010':'B','0100 0011':'C','0100 0100':'D','0100 0101':'E','0100 0110':'F','0100 0111':'G','0100 1000':'H','0100 1001':'I','0100 1010':'J','0100 1011':'K','0100 1100':'L','0100 1101':'M','0100 1110':'N','0100 1111':'O','0101 0000':'P','0101 0001':'Q','0101 0010':'R','0101 0011':'S','0101 0100':'T','0101 0101':'U','0101 0110':'V','0101 0111':'W','0101 1000':'X','0101 1001':'Y','0101 1010':'Z','0101 1011':'[','0101 1100':'\\','0101 1101':']','0101 1110':'^','0101 1111':'_','0110 0000':'`','0110 0001':'a','0110 0010':'b','0110 0011':'c','0110 0100':'d','0110 0101':'e','0110 0110':'f','0110 0111':'g','0110 1000':'h','0110 1001':'i','0110 1010':'j','0110 1011':'k','0110 1100':'l','0110 1101':'m','0110 1110':'n','0110 1111':'o','0111 0000':'p','0111 0001':'q','0111 0010':'r','0111 0011':'s','0111 0100':'t','0111 0101':'u','0111 0110':'v','0111 0111':'w','0111 1000':'x','0111 1001':'y','0111 1010':'z','0111 1011':'{','0111 1100':'|','0111 1101':'}','0111 1110':'~'}
ascii_ten_reverse = {'32':' ','33':'!','34':'"','35':'#','36':'$','37':'%','38':'&','39':"'",'40':'(','41':')','42':'*','43':'+','44':',','45':'-','46':'.','47':'/','48':'0','49':'1','50':'2','51':'3','52':'4','53':'5','54':'6','55':'7','56':'8','57':'9','58':':','59':';','60':'<','61':'=','62':'>','63':'?','64':'@','65':'A','66':'B','67':'C','68':'D','69':'E','70':'F','71':'G','72':'H','73':'I','74':'J','75':'K','76':'L','77':'M','78':'N','79':'O','80':'P','81':'Q','82':'R','83':'S','84':'T','85':'U','86':'V','87':'W','88':'X','89':'Y','90':'Z','91':'[','92':'\\','93':']','94':'^','95':'_','96':'`','97':'a','98':'b','99':'c','100':'d','101':'e','102':'f','103':'g','104':'h','105':'i','106':'j','107':'k','108':'l','109':'m','110':'n','111':'o','112':'p','113':'q','114':'r','115':'s','116':'t','117':'u','118':'v','119':'w','120':'x','121':'y','122':'z','123':'{','124':'|','125':'}','126':'~'}
ascii_sixteen_reverse = {'20':' ','21':'!','22':'"','23':'#','24':'$','25':'%','26':'&','27':"'",'28':'(','29':')','2a':'*','2b':'+','2c':',','2d':'-','2e':'.','2f':'/','30':'0','31':'1','32':'2','33':'3','34':'4','35':'5','36':'6','37':'7','38':'8','39':'9','3a':':','3b':';','3c':'<','3d':'=','3e':'>','3f':'?','40':'@','41':'A','42':'B','43':'C','44':'D','45':'E','46':'F','47':'G','48':'H','49':'I','4a':'J','4b':'K','4c':'L','4d':'M','4e':'N','4f':'O','50':'P','51':'Q','52':'R','53':'S','54':'T','55':'U','56':'V','57':'W','58':'X','59':'Y','5a':'Z','5b':'[','5c':'\\','5d':']','5e':'^','5f':'_','60':'`','61':'a','62':'b','63':'c','64':'d','65':'e','66':'f','67':'g','68':'h','69':'i','6a':'j','6b':'k','6c':'l','6d':'m','6e':'n','6f':'o','70':'p','71':'q','72':'r','73':'s','74':'t','75':'u','76':'v','77':'w','78':'x','79':'y','7a':'z','7b':'{','7c':'|','7d':'}','7e':'~'}

# 导入模块
from curses import window
import tkinter as tk

# 创建主窗口
window_main = tk.Tk()
window_main.title('ascii转换')
window_main.geometry('170x70')

def positive(): # 定义UTF-8转ascii函数
    # 创建选项窗口
    window_positive = tk.Tk()
    window_positive.title('UTF-8变ascii')
    window_positive.geometry('200x105')
    
    def positive_two(): # 定义UTF-8转二进制ascii函数
        # 创建窗口
        window_positive_two = tk.Tk()
        window_positive_two.title('UTF-8变二进制ascii')
        window_positive_two.geometry('480x700')

        def run(): # 定义转换程序
            a = e.get() # 定义a的值为用户输入的数据
            b = '' # 定义b为空字符串
            for i in a: # 将用户输入的值转换为ascii编码
                b = b + ascii_two_positive[i]
            print(a,'的二进制ascii编码是',b) # 在python运行窗口显示
            l = tk.Label(window_positive_two, text=b, bg='grey', width=50, height=1)
            l.pack() # 在python tkinter的窗口中显示
        
        e = tk.Entry(window_positive_two, show=None, bg='grey', width=50)
        e.pack() # 创建文本框获取用户输入的信息
        frequency = tk.Button(window_positive_two, text='开始转换', command=run)
        frequency.pack() # 创建按钮开始转换

        window_positive_two.mainloop() # 用mainloop重复刷新窗口

    def positive_ten(): # 定义UTF-8转十进制的ascii函数
        # 创建窗口
        window_positive_ten = tk.Tk()
        window_positive_ten.title('UTF-8变十进制ascii')
        window_positive_ten.geometry('480x700')

        def run(): # 定义转换程序
            a = e.get() # 定义a的值为用户输入的数据
            b = '' # 定义b为空字符串
            for i in a: # 将用户输入的数据转换为ascii编码
                b = b + ascii_ten_positive[i]
            print(a,'的十进制ascii编码是',b) # 在python运行窗口显示
            l = tk.Label(window_positive_ten, text=b, bg='grey', width=50, height=1)
            l.pack() # 在python tkinter的窗口中显示
        
        e = tk.Entry(window_positive_ten, show=None, bg='grey', width=50)
        e.pack() # 创建文本框获取用户输入的信息
        frequency = tk.Button(window_positive_ten, text='开始转换', command=run)
        frequency.pack() # 创建按钮开始转换

        window_positive_ten.mainloop() # 用mainloop重复刷新窗口

    def positive_sixteen(): # 定义UTF-8转十六进制的ascii函数
        # 创建窗口
        window_positive_sixteen = tk.Tk()
        window_positive_sixteen.title('UTF-8变十六进制ascii')
        window_positive_sixteen.geometry('480x700')

        def run(): # 定义转换程序
            a = e.get() # 定义a的值为用户输入的数据
            b = '' # 定义b为空字符串
            for i in a: # 将用户输入的值转换为ascii编码
                b = b + ascii_sixteen_positive[i]
            print(a,'的十六进制ascii编码是',b) # 在python运行窗口显示
            l = tk.Label(window_positive_sixteen, text=b, bg='grey', width=50, height=1)
            l.pack() # 在python tkinter的窗口中显示
        
        e = tk.Entry(window_positive_sixteen, show=None, bg='grey', width=50)
        e.pack() # 创建文本框获取用户输入的信息
        frequency = tk.Button(window_positive_sixteen, text='开始转换', command=run)
        frequency.pack() # 创建按钮开始转换

        window_positive_sixteen.mainloop() # 用mainloop重复刷新窗口

    frequency_two = tk.Button(window_positive, text='UTF-8变二进制ascii', command=positive_two)
    frequency_two.pack() # 创建按钮跳转至UTF-8转二进制ascii的窗口
    frequency_ten = tk.Button(window_positive, text='UTF-8变十进制ascii', command=positive_ten)
    frequency_ten.pack() # 创建按钮跳转至UTF-8转十进制ascii的窗口
    frequency_sixteen = tk.Button(window_positive, text='UTF-8变十六进制ascii', command=positive_sixteen)
    frequency_sixteen.pack() # 创建按钮跳转至UTF-8转十六进制ascii的窗口

    window_positive.mainloop() # 用mainloop重复刷新窗口

def reverse(): # 定义ascii转UTF-8函数
    # 创建选项窗口
    window_reverse = tk.Tk()
    window_reverse.title('ascii转UTF-8')
    window_reverse.geometry('200x105')

    def reverse_two(): # 定义二进制ascii转UTF-8函数
        # 创建窗口
        window_reverse_two = tk.Tk()
        window_reverse_two.title('二进制ascii转UTF-8')
        window_reverse_two.geometry('480x700')

        def run(): # 定义转换程序
            a = e.get() # 定义a的值为用户输入的数据
            b = '' # 定义b为空字符串
            for i in a: # 将用户输入的值转换为UTF-8编码
                b = b + ascii_two_reverse[i]
            print(a,'的UTF-8编码是',b) # 在python运行窗口显示
            l = tk.Label(window_reverse_two, text=b, bg='grey', width=50, height=1)
            l.pack() # 在python tkinter的窗口中显示
        
        e = tk.Entry(window_reverse_two, show=None, bg='grey', width=50)
        e.pack() # 创建文本框获取用户输入的信息
        frequency = tk.Button(window_reverse_two, text='开始转换', command=run)
        frequency.pack() # 创建按钮开始转换

        window_reverse_two.mainloop() # 用mainloop重复刷新窗口

    def reverse_ten(): # 定义十进制ascii转UTF-8函数
        # 创建窗口
        window_reverse_ten = tk.Tk()
        window_reverse_ten.title('十进制ascii转UTF-8')
        window_reverse_ten.geometry('480x700')

        def run(): # 定义转换程序
            a = e.get() # 定义a的值为用户输入的数据
            b = '' # 定义b为空字符串
            for i in a: # 将用户输入的数据转换为UTF-8编码
                b = b + ascii_ten_reverse[i]
            print(a,'的UTF-8编码是',b) # 在python运行窗口显示
            l = tk.Label(window_reverse_ten, text=b, bg='grey', width=50, height=1)
            l.pack() # 在python tkinter的窗口中显示
        
        e = tk.Entry(window_reverse_ten, show=None, bg='grey', width=50)
        e.pack() # 创建文本框获取用户输入的信息
        frequency = tk.Button(window_reverse_ten, text='开始转换', command=run)
        frequency.pack() # 创建按钮开始转换

        window_reverse_ten.mainloop() # 用mainloop重复刷新窗口

    def reverse_sixteen(): # 定义十六进制ascii转UTF-8函数
        # 创建窗口
        window_reverse_sixteen = tk.Tk()
        window_reverse_sixteen.title('十六进制ascii转UTF-8')
        window_reverse_sixteen.geometry('480x700')

        def run(): # 定义转换程序
            a = e.get() # 定义a的值为用户输入的数据
            b = '' # 定义b为空字符串
            for i in a: # 将用户输入的数据转换为UTF-8编码
                b = b + ascii_sixteen_reverse[i]
            print(a,'的UTF-8编码是',b) # 在python运行窗口显示
            l = tk.Label(window_reverse_sixteen, text=b, bg='grey', width=50, height=1)
            l.pack() # 在python tkinter的窗口中显示
        
        e = tk.Entry(window_reverse_sixteen, show=None, bg='grey', width=50)
        e.pack() # 创建文本框获取用户输入的信息
        frequency = tk.Button(window_reverse_sixteen, text='开始转换', command=run)
        frequency.pack() # 创建按钮开始转换

        window_reverse_sixteen.mainloop() # 用mainloop重复刷新窗口

    frequency_two = tk.Button(window_reverse, text='二进制ascii转UTF-8', command=reverse_two)
    frequency_two.pack() # 创建按钮跳转至二进制ascii转UTF-8的窗口
    frequency_ten = tk.Button(window_reverse, text='十进制ascii转UTF-8', command=reverse_ten)
    frequency_ten.pack() # 创建按钮跳转至十进制ascii转UTF-8的窗口
    frequency_sixteen = tk.Button(window_reverse, text='十六进制ascii转UTF-8', command=reverse_sixteen)
    frequency_sixteen.pack() # 创建按钮跳转至十六进制ascii转UTF-8的窗口

    window_reverse.mainloop() # 用mainloop重复刷新窗口

frequency_positive = tk.Button(window_main, text='UTF-8变ascii', command=positive)
frequency_positive.pack() # 创建按钮跳转至UTF-8转ascii的窗口
frequency_reverse = tk.Button(window_main, text='ascii转UTF-8', command=reverse)
frequency_reverse.pack() # 创建按钮跳转至ascii转UTF-8的窗口

window_main.mainloop() # 用mainloop重复刷新窗口
