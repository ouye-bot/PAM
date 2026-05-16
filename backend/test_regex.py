import re

line = "root     pts/0        172.21.0.1       Sat Apr 18 11:14:56 2026   gone - no logout"

pattern1 = r'^(\w+)\s+pts/(\d+)\s+([0-9.]+)\s+(\w+)\s+(\w+)\s+(\d+)\s+([\d:]+)\s+(\d+)'
match1 = re.match(pattern1, line)

if match1:
    print(f"方案1匹配成功: groups={match1.groups()}")
else:
    print("方案1匹配失败")

pattern2 = r'(\w+)\s+pts/(\d+)\s+([0-9.]+)\s+(\w+)\s+(\w+)\s+(\d+)\s+([\d:]+)'
match2 = re.search(pattern2, line)

if match2:
    print(f"方案2备用匹配成功: groups={match2.groups()}")
else:
    print("方案2备用匹配失败")

if 'pts/' in line:
    print("'pts/' 在行中")
else:
    print("'pts/' 不在行中")