# -*- coding: utf8 -*-
import math
import traceback
from datetime import datetime
import pytz
import uuid
import json
import random
import re
import time
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# 移除push_util导入（不再推送）
from util.aes_help import encrypt_data, decrypt_data
import util.zepp_helper as zeppHelper

# ===================== 加密配置（从环境变量读取，适配GitHub Actions） =====================
# 本地运行时可手动设置环境变量，CI运行时由GitHub Secrets注入
ENCRYPT_PASSWORD = os.getenv("ENCRYPT_PASSWORD", "local_test_password")
# 盐值：从环境变量读取字符串，再转为bytes（GitHub Secrets仅支持字符串）
ENCRYPT_SALT_STR = os.getenv("ENCRYPT_SALT", "local_test_salt_123456")
ENCRYPT_SALT = ENCRYPT_SALT_STR.encode()
# 加密账号密码文件路径（确保该文件已提交到GitHub仓库）
ENCRYPT_CONFIG_FILE = os.getenv("ENCRYPT_CONFIG_FILE", "encrypted_accounts.json")
# ======================================================================================

# 工具函数定义（先定义，后使用）
def get_int_value_default(_config: dict, _key, default):
    _config.setdefault(_key, default)
    return int(_config.get(_key))

def fake_ip():
    return f"{223}.{random.randint(64, 117)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def desensitize_user_name(user):
    if len(user) <= 8:
        ln = max(math.floor(len(user) / 3), 1)
        return f'{user[:ln]}***{user[-ln:]}'
    return f'{user[:3]}****{user[-4:]}'

def get_beijing_time():
    target_timezone = pytz.timezone('Asia/Shanghai')
    return datetime.now().astimezone(target_timezone)

def format_now():
    return get_beijing_time().strftime("%Y-%m-%d %H:%M:%S")

def get_time():
    current_time = get_beijing_time()
    return "%.0f" % (current_time.timestamp() * 1000)

def get_access_token(location):
    code_pattern = re.compile("(?<=access=).*?(?=&)")
    result = code_pattern.findall(location)
    if result is None or len(result) == 0:
        return None
    return result[0]

def get_error_code(location):
    code_pattern = re.compile("(?<=error=).*?(?=&)")
    result = code_pattern.findall(location)
    if result is None or len(result) == 0:
        return None
    return result[0]

def get_min_max_by_time(hour=None, minute=None):
    if hour is None:
        hour = time_bj.hour
    if minute is None:
        minute = time_bj.minute
    
    time_rate = min((hour * 60 + minute) / (22 * 60), 1)
    
    min_step = get_int_value_default(config, 'MIN_STEP', 18000)
    max_step = get_int_value_default(config, 'MAX_STEP', 25000)
    
    calc_min_step = int(time_rate * min_step)
    calc_max_step = int(time_rate * max_step)
    
    # 周日步数减半逻辑
    weekday = time_bj.weekday()
    if weekday == 6:
        calc_min_step = int(calc_min_step / 2)
        calc_max_step = int(calc_max_step / 2)
        calc_min_step = max(calc_min_step, 100)
    
    return calc_min_step, calc_max_step

# ========== 账号密码加密/解密工具函数 ==========
def generate_fernet_key(password: str, salt: bytes) -> bytes:
    """根据密码和盐值生成Fernet加密密钥"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_accounts(users_str: str, passwords_str: str, output_file: str):
    """加密账号密码并保存到文件（首次配置时使用）
    :param users_str: 明文账号串（#分隔）
    :param passwords_str: 明文密码串（#分隔）
    :param output_file: 加密文件保存路径
    """
    key = generate_fernet_key(ENCRYPT_PASSWORD, ENCRYPT_SALT)
    fernet = Fernet(key)
    # 加密账号和密码
    encrypted_users = fernet.encrypt(users_str.encode()).decode()
    encrypted_passwords = fernet.encrypt(passwords_str.encode()).decode()
    # 保存到JSON文件
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            "encrypted_users": encrypted_users,
            "encrypted_passwords": encrypted_passwords
        }, f, ensure_ascii=False, indent=2)
    print(f"✅ 账号密码已加密保存到 {output_file}")

def decrypt_accounts(input_file: str) -> tuple[str, str]:
    """从加密文件解密账号密码
    :return: (解密后的账号串, 解密后的密码串)
    """
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"❌ 加密配置文件 {input_file} 不存在！")
    
    # 读取加密文件
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # 生成密钥并解密
    key = generate_fernet_key(ENCRYPT_PASSWORD, ENCRYPT_SALT)
    fernet = Fernet(key)
    try:
        users_str = fernet.decrypt(data["encrypted_users"].encode()).decode()
        passwords_str = fernet.decrypt(data["encrypted_passwords"].encode()).decode()
        return users_str, passwords_str
    except Exception as e:
        raise ValueError(f"❌ 解密失败！请检查密码/盐值是否正确：{str(e)}")

# 全局变量初始化
config = {
    "MIN_STEP": 4000,  # 基础最小步数
    "MAX_STEP": 8000   # 基础最大步数
}
user_tokens = {}
use_concurrent = False  # 是否启用多线程并发
sleep_seconds = 1       # 串行执行时账号间隔秒数
encrypt_support = False # 是否启用token加密（需配置aes_key）
aes_key = ""            # AES加密密钥（encrypt_support=True时必填）
time_bj = get_beijing_time()  # 初始化北京时间

# 解密获取账号密码（核心：从加密文件读取，非明文）
users = ""
passwords = ""
try:
    print(f"🔑 开始解密账号密码（文件：{ENCRYPT_CONFIG_FILE}）")
    users, passwords = decrypt_accounts(ENCRYPT_CONFIG_FILE)
    print("✅ 账号密码解密成功！")
except Exception as e:
    print(f"❌ 账号密码解密失败：{str(e)}")
    print("\n===== 首次使用请执行以下步骤生成加密配置文件 =====")
    print("1. 配置环境变量 ENCRYPT_PASSWORD 和 ENCRYPT_SALT（本地/CI）")
    print("2. 取消下方注释，填写明文账号密码后运行一次代码")
    print("3. 运行后注释掉该代码，再次运行即可自动解密")
    # ===================== 首次配置用（运行后注释） =====================
    # plain_users = "+8613800138000#user@example.com"  # 你的明文账号（#分隔）
    # plain_passwords = "pwd123#pwd456"                # 你的明文密码（#分隔）
    # encrypt_accounts(plain_users, plain_passwords, ENCRYPT_CONFIG_FILE)
    # ==================================================================
    exit(1)

class MiMotionRunner:
    def __init__(self, _user, _passwd):
        self.user_id = None
        self.device_id = str(uuid.uuid4())
        user = str(_user)
        password = str(_passwd)
        self.invalid = False
        self.log_str = ""
        if user == '' or password == '':
            self.error = "用户名或密码填写有误！"
            self.invalid = True
            pass
        self.password = password
        if (user.startswith("+86")) or "@" in user:
            user = user
        else:
            user = "+86" + user
        if user.startswith("+86"):
            self.is_phone = True
        else:
            self.is_phone = False
        self.user = user

    def login(self):
        user_token_info = user_tokens.get(self.user)
        if user_token_info is not None:
            access_token = user_token_info.get("access_token")
            login_token = user_token_info.get("login_token")
            app_token = user_token_info.get("app_token")
            self.device_id = user_token_info.get("device_id")
            self.user_id = user_token_info.get("user_id")
            if self.device_id is None:
                self.device_id = str(uuid.uuid4())
                user_token_info["device_id"] = self.device_id
            ok, msg = zeppHelper.check_app_token(app_token)
            if ok:
                self.log_str += "使用加密保存的app_token\n"
                return app_token
            else:
                self.log_str += f"app_token失效 重新获取 last grant time: {user_token_info.get('app_token_time')}\n"
                app_token, msg = zeppHelper.grant_app_token(login_token)
                if app_token is None:
                    self.log_str += f"login_token 失效 重新获取 last grant time: {user_token_info.get('login_token_time')}\n"
                    login_token, app_token, user_id, msg = zeppHelper.grant_login_tokens(access_token, self.device_id,
                                                                                         self.is_phone)
                    if login_token is None:
                        self.log_str += f"access_token 已失效：{msg} last grant time:{user_token_info.get('access_token_time')}\n"
                    else:
                        user_token_info["login_token"] = login_token
                        user_token_info["app_token"] = app_token
                        user_token_info["user_id"] = user_id
                        user_token_info["login_token_time"] = get_time()
                        user_token_info["app_token_time"] = get_time()
                        self.user_id = user_id
                        return app_token
                else:
                    self.log_str += "重新获取app_token成功\n"
                    user_token_info["app_token"] = app_token
                    user_token_info["app_token_time"] = get_time()
                    return app_token

        access_token, msg = zeppHelper.login_access_token(self.user, self.password)
        if access_token is None:
            self.log_str += "登录获取accessToken失败：%s" % msg
            return None
        login_token, app_token, user_id, msg = zeppHelper.grant_login_tokens(access_token, self.device_id,
                                                                             self.is_phone)
        if login_token is None:
            self.log_str += f"登录提取的 access_token 无效：{msg}"
            return None

        user_token_info = dict()
        user_token_info["access_token"] = access_token
        user_token_info["login_token"] = login_token
        user_token_info["app_token"] = app_token
        user_token_info["user_id"] = user_id
        user_token_info["access_token_time"] = get_time()
        user_token_info["login_token_time"] = get_time()
        user_token_info["app_token_time"] = get_time()
        if self.device_id is None:
            self.device_id = uuid.uuid4()
        user_token_info["device_id"] = self.device_id
        user_tokens[self.user] = user_token_info
        return app_token

    def login_and_post_step(self, min_step, max_step):
        if self.invalid:
            return "账号或密码配置有误", False
        app_token = self.login()
        if app_token is None:
            return "登陆失败！", False

        step = str(random.randint(min_step, max_step))
        self.log_str += f"已设置为随机步数范围({min_step}~{max_step}) 随机值:{step}\n"
        ok, msg = zeppHelper.post_fake_brand_data(step, app_token, self.user_id)
        return f"修改步数（{step}）[" + msg + "]", ok

def run_single_account(total, idx, user_mi, passwd_mi):
    idx_info = ""
    if idx is not None:
        idx_info = f"[{idx + 1}/{total}]"
    log_str = f"[{format_now()}]\n{idx_info}账号：{desensitize_user_name(user_mi)}\n"
    try:
        runner = MiMotionRunner(user_mi, passwd_mi)
        min_step, max_step = get_min_max_by_time()
        exec_msg, success = runner.login_and_post_step(min_step, max_step)
        log_str += runner.log_str
        log_str += f'{exec_msg}\n'
        exec_result = {"user": user_mi, "success": success,
                       "msg": exec_msg}
    except:
        log_str += f"执行异常:{traceback.format_exc()}\n"
        log_str += traceback.format_exc()
        exec_result = {"user": user_mi, "success": False,
                       "msg": f"执行异常:{traceback.format_exc()}"}
    print(log_str)
    return exec_result

def execute():
    # 校验账号密码是否为空
    if not users or not passwords:
        print("❌ 错误：解密后的账号或密码为空！")
        exit(1)
    
    user_list = users.split('#')
    passwd_list = passwords.split('#')
    exec_results = []
    if len(user_list) == len(passwd_list):
        idx, total = 0, len(user_list)
        print(f"📢 开始执行步数修改，共 {total} 个账号")
        if use_concurrent:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                exec_results = executor.map(lambda x: run_single_account(total, x[0], *x[1]),
                                            enumerate(zip(user_list, passwd_list)))
        else:
            for user_mi, passwd_mi in zip(user_list, passwd_list):
                exec_results.append(run_single_account(total, idx, user_mi, passwd_mi))
                idx += 1
                if idx < total:
                    time.sleep(sleep_seconds)
        # 保存token缓存（若启用加密）
        if encrypt_support:
            persist_user_tokens()
        # 统计结果（仅控制台输出，无推送）
        success_count = 0
        for result in exec_results:
            if result['success'] is True:
                success_count += 1
        summary = f"\n===== 执行结果汇总 =====\n📊 执行账号总数：{total}\n✅ 成功：{success_count}\n❌ 失败：{total - success_count}"
        print(summary)
    else:
        print(f"❌ 错误：账号数[{len(user_list)}]和密码数[{len(passwd_list)}]不匹配！")
        exit(1)

def prepare_user_tokens() -> dict:
    data_path = r"encrypted_tokens.data"
    if os.path.exists(data_path) and encrypt_support and aes_key:
        with open(data_path, 'rb') as f:
            data = f.read()
        try:
            decrypted_data = decrypt_data(data, aes_key, None)
            return json.loads(decrypted_data.decode('utf-8', errors='strict'))
        except:
            print("⚠️ 提示：密钥不正确或者加密内容损坏，放弃加载token缓存")
            return dict()
    else:
        if not encrypt_support:
            print("ℹ️ 提示：未启用token加密，跳过加载缓存")
        elif not aes_key:
            print("ℹ️ 提示：未配置加密密钥，跳过加载token缓存")
        return dict()

def persist_user_tokens():
    data_path = r"encrypted_tokens.data"
    if not aes_key:
        print("❌ 错误：启用了token加密但未配置aes_key，无法保存缓存！")
        return
    try:
        encrypted_data = encrypt_data(json.dumps(user_tokens).encode('utf-8'), aes_key, None)
        with open(data_path, 'wb') as f:
            f.write(encrypted_data)
        print("✅ 提示：token已加密保存")
    except:
        print("❌ 错误：token加密保存失败：", traceback.format_exc())

# 初始化token缓存
user_tokens = prepare_user_tokens()

if __name__ == "__main__":
    execute()
