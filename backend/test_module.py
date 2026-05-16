import sys
import inspect

sys.path.insert(0, r'D:\PAM\pam-system\backend')

from app.services.bypass_detector import detect_bypass_for_asset

print(f"Module file: {inspect.getfile(detect_bypass_for_asset)}")

import app.services.bypass_detector as bd
print(f"Module file: {inspect.getfile(bd)}")

with open(inspect.getfile(bd), 'r') as f:
    content = f.read()
    if '解析行' in content:
        print("代码中包含'解析行'")
    elif '检查行' in content:
        print("代码中包含'检查行'")
    else:
        print("代码中既不包含'解析行'也不包含'检查行'")