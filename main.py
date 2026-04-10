                      
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

                                 
from util.aes_help import encrypt_data, decrypt_data
                                 
import util.zepp_helper as zeppHelper

                                                                               
                             
                                                                               
def get_int_value_default(_config: dict, _key, default):
                      
    _config.setdefault(_key, default)
              
    return int(_config.get(_key))

                                                                               
                                     
                                                                               
def get_min_max_by_time(hour=None, minute=None):
    global time_bj
    if hour is None:
        hour = time_bj.hour
    if minute is None:
        minute = time_bj.minute

                               
    time_rate = min((hour * 60 + minute) / (22 * 60), 1)

                                      
    min_step = get_int_value_default(config, 'MIN_STEP', 18000)
    max_step = get_int_value_default(config, 'MAX_STEP', 25000)

                              
    return int(time_rate * min_step), int(time_rate * max_step)

                                                                               
                             
                                                                               
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
    if not result:
        return None
    return result[0]

                                                                               
                    
                                                                               
def get_error_code(location):
    code_pattern = re.compile("(?<=error=).*?(?=&)")
    result = code_pattern.findall(location)
    if not result:
        return None
    return result[0]

                                                                               
                              
                                                                               
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

        self.password = password

                               
        if (user.startswith("+86")) or "@" in user:
            user = user
        else:
            user = "+86" + user

                    
        self.is_phone = user.startswith("+86")
        self.user = user

                                                                               
                                     
                                                                               
    def login(self):
        global user_tokens
                                   
        user_token_info = user_tokens.get(self.user)

        if user_token_info is not None:
                       
            access_token = user_token_info.get("access_token")
            login_token = user_token_info.get("login_token")
            app_token = user_token_info.get("app_token")
            self.device_id = user_token_info.get("device_id")

                            
            if self.device_id is None:
                self.device_id = str(uuid.uuid4())
                user_token_info["device_id"] = self.device_id

                             
            ok, msg = zeppHelper.check_app_token(app_token)
            if ok:
                self.log_str += "使用加密保存的app_token\n"
                return app_token
            else:
                self.log_str += "app_token已失效，尝试用login_token刷新\n"
                                          
                app_token, msg = zeppHelper.grant_app_token(login_token)

                if app_token is None:
                    self.log_str += "login_token已失效，尝试用access_token刷新\n"
                                                             
                    login_token, app_token, user_id, msg = zeppHelper.grant_login_tokens(
                        access_token, self.device_id, self.is_phone
                    )

                    if login_token is None:
                        self.log_str += "access_token也已失效，需要重新账号登录\n"
                    else:
                                     
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

                                   
        self.log_str += "无有效token，使用账号密码重新登录\n"
        access_token, msg = zeppHelper.login_access_token(self.user, self.password)
        if access_token is None:
            self.log_str += "账号密码登录获取accessToken失败：%s\n" % msg
            return None

                                 
        login_token, app_token, user_id, msg = zeppHelper.grant_login_tokens(
            access_token, self.device_id, self.is_phone
        )
        if login_token is None:
            self.log_str += "登录后获取业务token失败：%s\n" % msg
            return None

                           
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

                                                                               
                       
                                                                               
    def login_and_post_step(self, min_step, max_step):
                  
        if self.invalid:
            return "账号或密码配置有误", False

                         
        app_token = self.login()
        if app_token is None:
            return "登录失败！", False

                          
        step = str(random.randint(min_step, max_step))
        self.log_str += f"当前步数范围({min_step}~{max_step})，本次随机：{step}\n"

                      
        ok, msg = zeppHelper.post_fake_brand_data(step, app_token, self.user_id)
        return f"修改步数({step})[{msg}]", ok

                                                                               
            
                                                                               
def run_single_account(total, idx, user_mi, passwd_mi):
            
    idx_info = f"[{idx + 1}/{total}]" if idx is not None else ""
                    
    log_str = f"[{format_now()}]\n{idx_info}账号：{desensitize_user_name(user_mi)}\n"

    try:
                  
        runner = MiMotionRunner(user_mi, passwd_mi)
                 
        exec_msg, success = runner.login_and_post_step(min_step, max_step)
              
        log_str += runner.log_str
        log_str += f'{exec_msg}\n'
              
        exec_result = {
            "user": user_mi,
            "success": success,
            "msg": exec_msg
        }
    except Exception:
                             
        log_str += f"执行异常：{traceback.format_exc()}\n"
        exec_result = {
            "user": user_mi,
            "success": False,
            "msg": "执行异常"
        }

          
    print(log_str)
    return exec_result

                                                                               
          
                                                                               
def execute():
    global users, passwords, use_concurrent, sleep_seconds, encrypt_support

                 
    user_list = users.split('#')
    passwd_list = passwords.split('#')
    exec_results = []

                 
    if len(user_list) == len(passwd_list):
        idx, total = 0, len(user_list)

                     
        if use_concurrent:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                exec_results = executor.map(
                    lambda x: run_single_account(total, x[0], *x[1]),
                    enumerate(zip(user_list, passwd_list))
                )
        else:
                                   
            for user_mi, passwd_mi in zip(user_list, passwd_list):
                exec_results.append(run_single_account(total, idx, user_mi, passwd_mi))
                idx += 1
                if idx < total:
                    time.sleep(sleep_seconds)

                                
        if encrypt_support:
            persist_user_tokens()

                
        success_count = 0
        for result in exec_results:
            if result['success']:
                success_count += 1

        summary = f"\n执行完成：总数{total}，成功{success_count}，失败{total - success_count}"
        print(summary)
    else:
        print(f"账号数({len(user_list)})与密码数({len(passwd_list)})不匹配，退出")
        exit(1)

                                                                               
                   
                                                                               
def prepare_user_tokens() -> dict:
    data_path = r"encrypted_tokens.data"
    if os.path.exists(data_path):
        with open(data_path, 'rb') as f:
            data = f.read()
        try:
                   
            decrypted_data = decrypt_data(data, aes_key, None)
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception:
            print("密钥错误或文件损坏，清空token")
            return dict()
    else:
        return dict()

                                                                               
               
                                                                               
def persist_user_tokens():
    data_path = r"encrypted_tokens.data"
    origin_str = json.dumps(user_tokens, ensure_ascii=False)
           
    cipher_data = encrypt_data(origin_str.encode("utf-8"), aes_key, None)
    with open(data_path, 'wb') as f:
        f.write(cipher_data)

                                                                               
      
                                                                               
if __name__ == "__main__":
            
    time_bj = get_beijing_time()

    encrypt_support = False
    user_tokens = dict()
    aes_key = None

                             
    aes_env = os.environ.get("AES_KEY")
    if aes_env:
        aes_key = aes_env.encode('utf-8')
                    
        if len(aes_key) == 16:
            encrypt_support = True
        if encrypt_support:
                         
            user_tokens = prepare_user_tokens()
        else:
            print("AES_KEY长度无效，关闭加密保存")

                            
    config_env = os.environ.get("CONFIG")
    if not config_env:
        print("未配置CONFIG环境变量，退出")
        exit(1)

                 
    try:
        config = json.loads(config_env)
    except Exception:
        print("CONFIG格式不是合法JSON，请检查")
        exit(1)

                   
    sleep_seconds = config.get('SLEEP_GAP')
    if not sleep_seconds:
        sleep_seconds = 5
    sleep_seconds = float(sleep_seconds)

             
    users = config.get('USER')
    passwords = config.get('PWD')
    if not users or not passwords:
        print("未配置USER或PWD，退出")
        exit(1)

                  
    min_step, max_step = get_min_max_by_time()

             
    use_concurrent = (config.get('USE_CONCURRENT') == 'True')

    if not use_concurrent:
        print(f"多账号串行执行，间隔：{sleep_seconds}秒")

            
    execute()
