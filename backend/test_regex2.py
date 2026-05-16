import re

line = "root     pts/0        172.21.0.1       Sat Apr 18 17:59:58 2026   gone - no logout"
print(f"测试行: {line}")
print(f"长度: {len(line)}")

pattern = r'^(\w+)\s+pts/(\d+)\s+([0-9.]+)\s+(\w+)\s+(\w+)\s+(\d+)\s+([\d:]+)\s+(\d+)\s+.*'
match = re.match(pattern, line)

if match:
    print(f"匹配成功!")
    print(f"  user: {match.group(1)}")
    print(f"  pts: {match.group(2)}")
    print(f"  ip: {match.group(3)}")
    print(f"  dow: {match.group(4)}")
    print(f"  mon: {match.group(5)}")
    print(f"  day: {match.group(6)}")
    print(f"  time: {match.group(7)}")
    print(f"  year: {match.group(8)}")
else:
    print("匹配失败!")

    pattern2 = r'^(\w+)\s+pts/(\d+)\s+([0-9.]+)\s+(\w+)\s+(\w+)\s+(\d+)\s+([\d:]+)\s+(\d+)'
    match2 = re.match(pattern2, line)
    if match2:
        print(f"方案2匹配: groups={match2.groups()}")
    else:
        print("方案2也失败")