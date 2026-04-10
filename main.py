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

# 引入AES加解密工具，用于加密保存登录token，避免重复登录
from util.aes_help import encrypt_data, decrypt_data
# 引入Zepp运动相关接口封装（登录、刷新token、上传步数）
import util.zepp_helper as zeppHelper

# -----------------------------------------------------------------------------
# 工具函数：从配置中获取int类型值，不存在则使用默认值
# -----------------------------------------------------------------------------
def get_int_value_default(_config: dict, _key, default):
    # 若配置中无该key，则设置默认值
    _config.setdefault(_key, default)
    # 转为int并返回
    return int(_config.get(_key))

# -----------------------------------------------------------------------------
# 根据当前北京时间，计算当前应刷的步数范围（越晚步数越高，模拟真实行走）
# -----------------------------------------------------------------------------
def get_min_max_by_time(hour=None, minute=None):
    global time_bj
    if hour is None:
        hour = time_bj.hour
    if minute is None:
        minute = time_bj.minute

    # 计算时间比例：0点=0，22点=1，22点后保持1
    time_rate = min((hour * 60 + minute) / (22 * 60), 1)

    # 从配置读取最小/最大步数，无配置则使用默认18000~25000
    min_step = get_int_value_default(config, 'MIN_STEP', 18000)
    max_step = get_int_value_default(config, 'MAX_STEP', 25000)

    # 根据时间比例计算当前时段应刷的最小、最大随机步数
    return int(time_rate * min_step), int(time_rate * max_step)

# -----------------------------------------------------------------------------
# 生成随机国内IP，用于伪装请求来源（脚本中未实际使用）
# -----------------------------------------------------------------------------
def fake_ip():
    return f"{223}.{random.randint(64, 117)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

# -----------------------------------------------------------------------------
# 账号脱敏：日志中不显示完整手机号/邮箱
# -----------------------------------------------------------------------------
def desensitize_user_name(user):
    if len(user) <= 8:
        ln = max(math.floor(len(user) / 3), 1)
        return f'{user[:ln]}***{user[-ln:]}'
    # 长度>8时，前3位+****+后4位
    return f'{user[:3]}****{user[-4:]}'

# -----------------------------------------------------------------------------
# 获取北京时间（解决服务器时区问题）
# -----------------------------------------------------------------------------
def get_beijing_time():
    target_timezone = pytz.timezone('Asia/Shanghai')
    return datetime.now().astimezone(target_timezone)

# -----------------------------------------------------------------------------
# 格式化当前时间，用于日志打印
# -----------------------------------------------------------------------------
def format_now():
    return get_beijing_time().strftime("%Y-%m-%d %H:%M:%S")

# -----------------------------------------------------------------------------
# 获取13位时间戳，用于Zepp接口请求
# -----------------------------------------------------------------------------
def get_time():
    current_time = get_beijing_time()
    return "%.0f" % (current_time.timestamp() * 1000)

# -----------------------------------------------------------------------------
# 正则从跳转链接中提取 access_token
# -----------------------------------------------------------------------------
def get_access_token(location):
    code_pattern = re.compile("(?<=access=).*?(?=&)")
    result = code_pattern.findall(location)
    if not result:
        return None
    return result[0]

# -----------------------------------------------------------------------------
# 正则从跳转链接中提取错误码error
# -----------------------------------------------------------------------------
def get_error_code(location):
    code_pattern = re.compile("(?<=error=).*?(?=&)")
    result = code_pattern.findall(location)
    if not result:
        return None
    return result[0]

# -----------------------------------------------------------------------------
# 核心类：单个Zepp账号的登录、token管理、步数上传
# -----------------------------------------------------------------------------
class MiMotionRunner:
    def __init__(self, _user, _passwd):
        self.user_id = None              # Zepp用户ID
        self.device_id = str(uuid.uuid4())# 随机设备ID，模拟不同设备
        user = str(_user)
        password = str(_passwd)
        self.invalid = False             # 账号是否无效标记
        self.log_str = ""                # 日志内容

        # 账号或密码为空，标记为无效
        if user == '' or password == '':
            self.error = "用户名或密码填写有误！"
            self.invalid = True

        self.password = password

        # 非邮箱且不带+86的手机号，自动添加+86
        if (user.startswith("+86")) or "@" in user:
            user = user
        else:
            user = "+86" + user

        # 标记是否为手机号登录
        self.is_phone = user.startswith("+86")
        self.user = user

    # -------------------------------------------------------------------------
    # 登录逻辑：优先使用缓存token，逐级刷新，最后才账号密码登录
    # -------------------------------------------------------------------------
    def login(self):
        global user_tokens
        # 从全局token缓存中获取当前账号的token信息
        user_token_info = user_tokens.get(self.user)

        if user_token_info is not None:
            # 取出各级token
            access_token = user_token_info.get("access_token")
            login_token = user_token_info.get("login_token")
            app_token = user_token_info.get("app_token")
            self.device_id = user_token_info.get("device_id")

            # 设备ID为空则重新生成并保存
            if self.device_id is None:
                self.device_id = str(uuid.uuid4())
                user_token_info["device_id"] = self.device_id

            # 检查app_token是否有效
            ok, msg = zeppHelper.check_app_token(app_token)
            if ok:
                self.log_str += "使用加密保存的app_token\n"
                return app_token
            else:
                self.log_str += "app_token已失效，尝试用login_token刷新\n"
                # 使用login_token刷新app_token
                app_token, msg = zeppHelper.grant_app_token(login_token)

                if app_token is None:
                    self.log_str += "login_token已失效，尝试用access_token刷新\n"
                    # 使用access_token获取新的login_token和app_token
                    login_token, app_token, user_id, msg = zeppHelper.grant_login_tokens(
                        access_token, self.device_id, self.is_phone
                    )

                    if login_token is None:
                        self.log_str += "access_token也已失效，需要重新账号登录\n"
                    else:
                        # 保存新token到缓存
                        user_token_info["login_token"] = login_token
                        user_token_info["app_token"] = app_token
                        user_token_info["user_id"] = user_id
                        user_token_info["login_token_time"] = get_time()
                        user_token_info["app_token_time"] = get_time()
                        self.user_id = user_id
                        return app_token
                else:
                    self.log_str += "login_token刷新app_token成功\n"
                    user_token_info["app_token"] = app_token
                    user_token_info["app_token_time"] = get_time()
                    return app_token

        # 以上所有token都失效 → 使用账号密码重新登录
        self.log_str += "无有效token，使用账号密码重新登录\n"
        access_token, msg = zeppHelper.login_access_token(self.user, self.password)
        if access_token is None:
            self.log_str += "账号密码登录获取accessToken失败：%s\n" % msg
            return None

        # 用新的access_token换取完整登录凭证
        login_token, app_token, user_id, msg = zeppHelper.grant_login_tokens(
            access_token, self.device_id, self.is_phone
        )
        if login_token is None:
            self.log_str += "登录后获取业务token失败：%s\n" % msg
            return None

        # 构造token信息并保存到全局缓存
        user_token_info = {
            "access_token": access_token,
            "login_token": login_token,
            "app_token": app_token,
            "user_id": user_id,
            "access_token_time": get_time(),
            "login_token_time": get_time(),
            "app_token_time": get_time(),
            "device_id": self.device_id
        }
        user_tokens[self.user] = user_token_info
        self.log_str += "账号密码登录成功，已保存新token\n"
        return app_token

    # -------------------------------------------------------------------------
    # 登录并提交随机步数（对外核心方法）
    # -------------------------------------------------------------------------
    def login_and_post_step(self, min_step, max_step):
        # 账号无效直接返回
        if self.invalid:
            return "账号或密码配置有误", False

        # 执行登录获取app_token
        app_token = self.login()
        if app_token is None:
            return "登录失败！", False

        # 在min~max之间生成随机步数
        step = str(random.randint(min_step, max_step))
        self.log_str += f"当前步数范围({min_step}~{max_step})，本次随机：{step}\n"

        # 调用Zepp接口上传步数
        ok, msg = zeppHelper.post_fake_brand_data(step, app_token, self.user_id)
        return f"修改步数({step})[{msg}]", ok

# -----------------------------------------------------------------------------
# 执行单个账号刷步任务
# -----------------------------------------------------------------------------
def run_single_account(total, idx, user_mi, passwd_mi):
    # 构造序号信息
    idx_info = f"[{idx + 1}/{total}]" if idx is not None else ""
    # 日志开头：时间 + 脱敏账号
    log_str = f"[{format_now()}]\n{idx_info}账号：{desensitize_user_name(user_mi)}\n"

    try:
        # 创建账号运行实例
        runner = MiMotionRunner(user_mi, passwd_mi)
        # 执行登录+刷步
        exec_msg, success = runner.login_and_post_step(min_step, max_step)
        # 拼接日志
        log_str += runner.log_str
        log_str += f'{exec_msg}\n'
        # 构造结果
        exec_result = {
            "user": user_mi,
            "success": success,
            "msg": exec_msg
        }
    except Exception:
        # 捕获异常，避免单个账号崩溃导致整体退出
        log_str += f"执行异常：{traceback.format_exc()}\n"
        exec_result = {
            "user": user_mi,
            "success": False,
            "msg": "执行异常"
        }

    # 打印日志
    print(log_str)
    return exec_result

# -----------------------------------------------------------------------------
# 批量执行所有账号
# -----------------------------------------------------------------------------
def execute():
    global users, passwords, use_concurrent, sleep_seconds, encrypt_support

    # 按#分割多账号、多密码
    user_list = users.split('#')
    passwd_list = passwords.split('#')
    exec_results = []

    # 账号与密码数量必须一致
    if len(user_list) == len(passwd_list):
        idx, total = 0, len(user_list)

        # 是否开启多线程并发执行
        if use_concurrent:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                exec_results = executor.map(
                    lambda x: run_single_account(total, x[0], *x[1]),
                    enumerate(zip(user_list, passwd_list))
                )
        else:
            # 串行执行，每个账号之间间隔一段时间，防风控
            for user_mi, passwd_mi in zip(user_list, passwd_list):
                exec_results.append(run_single_account(total, idx, user_mi, passwd_mi))
                idx += 1
                if idx < total:
                    time.sleep(sleep_seconds)

        # 如果开启AES加密，持久化保存最新token
        if encrypt_support:
            persist_user_tokens()

        # 统计成功数量
        success_count = 0
        for result in exec_results:
            if result['success']:
                success_count += 1

        summary = f"\n执行完成：总数{total}，成功{success_count}，失败{total - success_count}"
        print(summary)
    else:
        print(f"账号数({len(user_list)})与密码数({len(passwd_list)})不匹配，退出")
        exit(1)

# -----------------------------------------------------------------------------
# 从加密文件读取之前保存的token
# -----------------------------------------------------------------------------
def prepare_user_tokens() -> dict:
    data_path = r"encrypted_tokens.data"
    if os.path.exists(data_path):
        with open(data_path, 'rb') as f:
            data = f.read()
        try:
            # AES解密
            decrypted_data = decrypt_data(data, aes_key, None)
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception:
            print("密钥错误或文件损坏，清空token")
            return dict()
    else:
        return dict()

# -----------------------------------------------------------------------------
# 将token加密保存到文件
# -----------------------------------------------------------------------------
def persist_user_tokens():
    data_path = r"encrypted_tokens.data"
    origin_str = json.dumps(user_tokens, ensure_ascii=False)
    # AES加密
    cipher_data = encrypt_data(origin_str.encode("utf-8"), aes_key, None)
    with open(data_path, 'wb') as f:
        f.write(cipher_data)

# -----------------------------------------------------------------------------
# 程序入口
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # 获取北京时间
    time_bj = get_beijing_time()

    encrypt_support = False
    user_tokens = dict()
    aes_key = None

    # 读取环境变量AES_KEY，用于token加密
    aes_env = os.environ.get("AES_KEY")
    if aes_env:
        aes_key = aes_env.encode('utf-8')
        # AES密钥必须16位
        if len(aes_key) == 16:
            encrypt_support = True
        if encrypt_support:
            # 加载本地加密token
            user_tokens = prepare_user_tokens()
        else:
            print("AES_KEY长度无效，关闭加密保存")

    # 读取CONFIG环境变量（JSON格式配置）
    config_env = os.environ.get("CONFIG")
    if not config_env:
        print("未配置CONFIG环境变量，退出")
        exit(1)

    # 解析CONFIG为字典
    try:
        config = json.loads(config_env)
    except Exception:
        print("CONFIG格式不是合法JSON，请检查")
        exit(1)

    # 读取账号间隔时间，默认5秒
    sleep_seconds = config.get('SLEEP_GAP')
    if not sleep_seconds:
        sleep_seconds = 5
    sleep_seconds = float(sleep_seconds)

    # 读取账号、密码
    users = config.get('USER')
    passwords = config.get('PWD')
    if not users or not passwords:
        print("未配置USER或PWD，退出")
        exit(1)

    # 根据当前时间计算步数范围
    min_step, max_step = get_min_max_by_time()

    # 是否多线程并发
    use_concurrent = (config.get('USE_CONCURRENT') == 'True')

    if not use_concurrent:
        print(f"多账号串行执行，间隔：{sleep_seconds}秒")

    # 开始批量执行
    execute()
