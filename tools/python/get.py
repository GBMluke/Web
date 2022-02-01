import requests

url = input('请输入目标网站 ')
# 输入对应的参数
data = dict(
    a='a'
)

response = requests.get(url , params=data)
print(response.text)
