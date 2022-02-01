import requests

url = input('请输入目标网站 ')
# 输入对应的参数
payload = {
    'a': 'a'
}
r = requests.post(url , data=payload)
print(r.text)
