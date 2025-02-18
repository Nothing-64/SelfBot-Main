import requests
from datetime import timedelta, datetime
import platform
import concurrent.futures
import threading
import re
import time
import uuid
import httpx
import base64
import tls_client
import asyncio
import random
from requests.exceptions import RequestException
import socket
import os
import shutil
import json
import psycopg2
import sys
import math
from bs4 import BeautifulSoup
import string
from captcha.image import ImageCaptcha
import io
import pytz
import zipfile
import hashlib
import hmac
from deep_translator import GoogleTranslator
import yt_dlp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import instaloader
from geopy.geocoders import Nominatim

selfcord_dir = 'selfcord'

if not os.path.exists(selfcord_dir):
    print("잠시만 기다려주세요... 라이브러리를 다운로드 중입니다...")

    url = 'https://github.com/Nothing-64/selfcord.py/archive/refs/heads/main.zip'
    response = requests.get(url)

    with open('selfcord.py-main.zip', 'wb') as f:
        f.write(response.content)

    with zipfile.ZipFile('selfcord.py-main.zip', 'r') as zip_ref:
        zip_ref.extractall()

    os.remove('selfcord.py-main.zip')

    extracted_dir = 'selfcord.py-main/selfcord'
    if os.path.exists(extracted_dir):
        shutil.move(extracted_dir, selfcord_dir)
    shutil.rmtree('selfcord.py-main')
else:
    pass

try:
    import selfcord
    from selfcord import *
    from selfcord.ext import commands, tasks
    from selfcord.ext.commands import Bot

except Exception as e:
    print(f"오류 발생: {e}")



client = selfcord.Client()
bot = commands.Bot(command_prefix=";", self_bot=True)


delete_confirmation = False
captcha_confirmation = False
captcha_text = ""
bot.help_command = None  
spamming_task = None 

def load_config():
    with open("config.json", "r", encoding='utf-8-sig') as f:
        return json.load(f)

config = load_config()
TOKEN = config["token"]  
GOOGLE_API_KEY = config.get("GOOGLE_API_KEY", "")
GOOGLE_CX = config.get("GOOGLE_CX", "")
STATUS_MAP = {
    "온라인": "online",
    "자리비움": "idle",
    "방해금지": "dnd",
    "오프라인": "invisible"
}
IPV4_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
IPV6_PATTERN = re.compile(r"^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$")


PRIVATE_IP_RANGES = [
    "10.", "127.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168."
]

LIB_VER = "1.7.3"
LOCAL_VER = "0.7.6"
class WIN_headers:
    def __init__(self):
        st = time.time()
        self.native_builds = self.native_build()
        self.main_versions = self.main_version()
        self.client_builds = self.client_build()
        self.chrome = WIN_headers.chrome_version()
        self.electron = "22.3.26"
        self.safari = "537.36"
        self.os_version = "10.0.19045"
        self.user_agent = f"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/{self.safari} (KHTML, like Gecko) Discord/{self.main_versions} Chrome/{self.chrome} Electron/{self.electron} Safari/{self.safari}"
        rn = str(time.time() - st)
        

        self.x_super_properties = self.desktop_xprops()
        self.dict = self.returner()

    @staticmethod
    def chrome_version() -> str:
        try:
            r = requests.get("https://versionhistory.googleapis.com/v1/chrome/platforms/linux/channels/stable/versions")
            data = json.loads(r.text)
            return data['versions'][0]['version']
        except Exception:
            return "108.0.5359.215"

    def desktop_xprops(self):
        return base64.b64encode(json.dumps({
            "os":"Windows",
            "browser":"discord Client",
            "release_channel":"stable",
            "client_version":self.main_versions,
            "os_version":self.os_version,
            "os_arch":"x64",
            "app_arch":"ia32",
            "system_locale":"en",
            "browser_user_agent":self.user_agent,
            "browser_version":self.electron,
            "client_build_number":self.client_builds,
            "native_build_number":self.native_builds,
            "client_event_source":None,
            "design_id":0
        }).encode()).decode()
    
    def native_build(self) -> int:
        return int(requests.get(
            "https://updates.discord.com/distributions/app/manifests/latest",
            params = {
                "install_id":'0',
                "channel":"stable",
                "platform":"win",
                "arch":"x86"
            },
            headers = {
                "user-agent": "discord-Updater/1",
                "accept-encoding": "gzip"
        }).json()["metadata_version"])

    def client_build(self) -> int:
        page = requests.get("https://discord.com/app").text.split("app-mount")[1]
        assets = re.findall(r'src="/assets/([^"]+)"', page)[::-1]

        for asset in assets:
            js = requests.get(f"https://discord.com/assets/{asset}").text
            
            if "buildNumber:" in js:
                return int(js.split('buildNumber:"')[1].split('"')[0])

    def main_version(self) -> str:
        app = requests.get(
            "https://discord.com/api/downloads/distributions/app/installers/latest",
            params = {
                "channel":"stable",
                "platform":"win",
                "arch":"x86"
            },
            allow_redirects = False
        ).text

        return re.search(r'x86/(.*?)/', app).group(1)
    
    def returner(self):
        return {
            'authority': 'discord.com',
            'accept': '*/*',
            'accept-language': 'en,en-US;q=0.9',
            'content-type': 'application/json',
            'origin': 'https://discord.com',
            'referer': 'https://discord.com/',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': self.user_agent,
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'en-US',
            'x-discord-timezone': 'Europe/Stockholm',
            'x-super-properties': self.x_super_properties
        }

    def __call__(self):
        return self.dict

def get_headers():
    return WIN_headers()()

headers = get_headers()

class Client:
    @staticmethod
    def get_session(token: str = "", cookie: bool = True):
        ident = {
            "Windows": f"chrome_{WIN_headers.chrome_version()[:3]}"
        }["Windows"]  

        session = tls_client.Session(
            client_identifier=ident,
            random_tls_extension_order=True
        )
        
        session.headers = headers
        if token:
            session.headers.update({"Authorization": token})
        if cookie:
            site = session.get("https://discord.com")
            session.cookies = site.cookies

        return session

def load_prefix():
    try:
        with open('Prefix.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('prefix', ';')  
    except FileNotFoundError:
        return ';'


def save_prefix(new_prefix):
    with open('Prefix.json', 'w', encoding='utf-8') as f:
        json.dump({'prefix': new_prefix}, f, ensure_ascii=False, indent=4)


def load_allowed_users():
    try:
        with open('userID.txt', 'r') as f:
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        return []

@bot.command()
async def 초대링크생성(ctx):
    sesheaders = get_headers().copy()
    sesheaders.update({'Authorization': TOKEN})
    channels = requests.get(f"https://discord.com/api/v9/guilds/{ctx.guild.id}/channels", headers=sesheaders).json()
    
    for channel in channels:
        if channel["type"] == 0:
            channel_id = channel["id"]
            break
    else:
        await ctx.reply("```초대 링크를 생성할 수 있는 채널을 찾을 수 없습니다.```")
        return

    invite_payload = {"max_age": 0, "max_uses": 0, "temporary": False}
    response = requests.post(f"https://discord.com/api/v9/channels/{channel_id}/invites", headers=sesheaders, json=invite_payload)

    if response.status_code == 200:
        invite_code = response.json()["code"]
        await ctx.reply(f"```초대 링크가 생성되었습니다: https://discord.gg/{invite_code}```")
    else:
        await ctx.reply(f"```초대 링크 생성에 실패하였습니다. 오류 코드: {response.status_code}```")

@bot.command()
async def 웹후크정보(ctx, url: str = None):
    if not url:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법 : {current_prefix}웹후크정보 [조회할 웹후크의 URL]```")
        return
    try:
        parts = url.split("/")
        if len(parts) < 2:
            return await ctx.reply("```올바른 웹후크 URL을 입력하세요.```")

        webhook_id, webhook_token = parts[-2], parts[-1]
        api_url = f"https://discord.com/api/webhooks/{webhook_id}/{webhook_token}"
        response = requests.get(api_url)

        if response.status_code == 200:
            data = response.json()
            info = (
                f"```\n"
                f"웹후크 이름: {data.get('name')}\n"
                f"채널 ID: {data.get('channel_id')}\n"
                f"길드 ID: {data.get('guild_id')}\n"
                f"```"
            )
            await ctx.reply(info)
        else:
            await ctx.reply(f"```웹후크 정보를 가져오는 데 실패했습니다. 상태 코드: {response.status_code}```")

    except Exception as e:
        await ctx.reply(f"```오류 발생: {e}```")


@bot.command()
async def 서버이름변경(ctx, *, new_name: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if not new_name:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법 : {current_prefix}서버이름변경 [변경할 서버 이름]```")
        return
    if not (2 <= len(new_name) <= 100):
        await ctx.reply("```서버 이름은 최소 2자 이상, 최대 100자 이하로 설정해야 합니다.```")
        return

    guild_id = ctx.guild.id
    sesheaders = get_headers().copy()
    sesheaders.update({'Authorization': TOKEN})

    payload = {"name": new_name}

    response = requests.patch(f"https://discord.com/api/v9/guilds/{guild_id}", headers=sesheaders, json=payload)

    if response.status_code == 200:
        await ctx.reply(f"```서버 이름이 `{new_name}`(으)로 변경되었습니다.```")
    else:
        await ctx.reply(f"```서버 이름 변경 실패. 오류 코드: {response.status_code} | 응답: {response.text}```")

@bot.command()
async def 서버프로필변경(ctx, image_url: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if not image_url:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법 : {current_prefix}서버프로필변경 [프로필 URL]```")
        return
    guild_id = ctx.guild.id
    sesheaders = get_headers().copy() 
    sesheaders.update({'Authorization': TOKEN}) 

    if not re.match(r"^(https?://).+\.(jpg|jpeg|png|gif|webp)$", image_url):
        await ctx.reply("```유효한 이미지 URL을 입력하세요. (jpg, png, gif, webp 형식만 지원)```")
        return

    image_data = requests.get(image_url).content
    image_base64 = base64.b64encode(image_data).decode()

    payload = {"icon": f"data:image/png;base64,{image_base64}"}

    response = requests.patch(f"https://discord.com/api/v9/guilds/{guild_id}", headers=sesheaders, json=payload)

    if response.status_code == 200:
        await ctx.reply("```서버 프로필이 성공적으로 변경되었습니다.```")
    else:
        await ctx.reply(f"```서버 프로필 변경 실패. 오류 코드: {response.status_code} | 응답: {response.text}```")


@bot.command()
async def 유저역할(ctx, action: str = None, role_input: str = None, member_input: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if not action or not role_input or not member_input:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법 : {current_prefix}유저역할 [지급 / 제거] [역할 ID 혹은 역할 이름] [사용자 멘션 혹은 사용자 ID]```")
        return

    guild = ctx.guild

    role = None
    if role_input.isdigit(): 
        role = selfcord.utils.get(guild.roles, id=int(role_input))
    if not role:  
        role = selfcord.utils.get(guild.roles, name=role_input)

    if not role:
        await ctx.reply(f"```해당 역할을 찾을 수 없습니다: {role_input}```")
        return

    try:
        member = await guild.fetch_member(int(member_input.strip('<@!>')) if member_input.isdigit() else None)
        if not member:
            await ctx.reply(f"```해당 사용자를 찾을 수 없습니다: {member_input}```")
            return
    except Exception as e:
        await ctx.reply(f"```사용자 조회 중 오류가 발생했습니다: {str(e)}```")
        return

    try:
        if action == "지급":
            await member.add_roles(role)
            await ctx.reply(f"```사용자 {member.display_name}에게 역할 `{role.name}`을(를) 지급했습니다.```")
        elif action == "제거":
            await member.remove_roles(role)
            await ctx.reply(f"```사용자 {member.display_name}에게서 역할 `{role.name}`을(를) 제거했습니다.```")
        else:
            await ctx.reply("```올바른 액션을 입력하세요: 지급 / 제거```")
    except Exception as e:
        await ctx.reply(f"```역할 지급/제거 실패. 오류: {str(e)}```")


@bot.command()
async def 서버나가기(ctx, guild_id: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if not guild_id:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법 : {current_prefix}서버나가기 [나갈 서버의 ID]```")
        return

    sesheaders = headers.copy()
    sesheaders.update({"Authorization": TOKEN})

    response = requests.delete(f"https://discord.com/api/v9/users/@me/guilds/{guild_id}", headers=sesheaders, json={})

    if response.status_code == 204:
        await ctx.reply(f"```서버(ID: `{guild_id}`)에서 성공적으로 나갔습니다.```")
    else:
        await ctx.reply(f"```서버 나가기 실패. 오류 코드: {response.status_code}, 응답: {response.text}```")


@bot.command()
async def 서버삭제(ctx):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    global delete_confirmation
    global captcha_confirmation
    global captcha_text

    if ctx.guild.owner_id == ctx.author.id:
        await ctx.reply("```정말 서버를 삭제하시겠습니까? (예/아니오)```")

        delete_confirmation = True 
        captcha_confirmation = False 
        captcha_text = "" 
    else:
        await ctx.reply("```이 서버의 소유자만 서버를 삭제할 수 있습니다.```")

@bot.event
async def on_message(message):
    global delete_confirmation
    global captcha_confirmation
    global captcha_text

    if message.author != bot.user:
        return

    if delete_confirmation:
        if message.content.lower() in ['예', '아니오']:
            if message.content.lower() == '아니오':
                await message.channel.send("```서버 삭제가 취소되었습니다.```")
                delete_confirmation = False
                return

            if message.content.lower() == '예':
                captcha_text = ''.join(random.choices(string.ascii_lowercase, k=6))

                image = ImageCaptcha()
                captcha_image = image.generate(captcha_text)
                captcha_bytes = io.BytesIO(captcha_image.read())
                captcha_image.close()
                await message.channel.send("```Captcha 인증을 진행합니다. 아래 이미지를 보고 6자리 소문자 코드를 입력하세요.```")
                await message.channel.send(file=selfcord.File(captcha_bytes, filename="captcha.png"))

                await message.channel.send("```Captcha 코드 입력을 기다립니다...```")

                delete_confirmation = False 
                captcha_confirmation = True 
                return

    if captcha_confirmation:
        if message.content.lower() == captcha_text:
            try:
                await message.guild.delete()
            except selfcord.HTTPException as e:
                if e.status == 401 and e.code == 60003:
                    await message.channel.send("```서버 삭제 작업에는 2단계 인증이 필요합니다. 2FA 인증을 완료하고 다시 시도해 주세요.```")
                else:
                    await message.channel.send(f"```서버 삭제 중 오류가 발생했습니다: {str(e)}```")
        else:
            await message.channel.send("```Captcha 코드가 틀렸습니다. 서버 삭제가 취소되었습니다.```")
        
        captcha_confirmation = False 

    await bot.process_commands(message)
@bot.command()
async def 상태(ctx, status: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if status not in STATUS_MAP or not status:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법 : {current_prefix}상태 [온라인 / 자리비움 / 방해금지 / 오프라인]```")
        return

    headers = {
        "Authorization": f"{TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "status": STATUS_MAP[status]
    }

    response = requests.patch("https://discord.com/api/v9/users/@me/settings", headers=headers, json=payload)

    if response.status_code == 200:
        await ctx.reply(f"```상태가 {status}(으)로 변경되었습니다.```")
    else:
        await ctx.reply(f"```상태 변경 실패. 오류 코드: {response.status_code}```")


@bot.command()
async def 검색(ctx, *, query: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if query is None:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}검색 [검색할 내용]```")  
        return

    if GOOGLE_CX:  
        search_url = "https://www.googleapis.com/customsearch/v1"
        params = {
            "q": query,
            "key": GOOGLE_API_KEY,
            "cx": GOOGLE_CX,
            "num": 3,  
        }

        response = requests.get(search_url, params=params)
        data = response.json()

        if "items" not in data:
            await ctx.reply("```검색 결과를 찾을 수 없습니다.```")
            return

        results = []
        for item in data["items"]:
            title = item["title"]
            link = item["link"]
            results.append(f"{title} - ({link})")

        await ctx.reply("\n".join(results))

    else:  
        search_url = f"https://www.google.com/search?q={query}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
        }

        response = requests.get(search_url, headers=headers)
        soup = BeautifulSoup(response.text, "html.parser")

        results = []
        for g in soup.find_all("div", class_="tF2Cxc")[:3]:  
            title = g.find("h3").text
            link = g.find("a")["href"]
            results.append(f"{title} - ({link})")

        if not results:
            await ctx.reply("```검색 결과를 찾을 수 없습니다.```")
            return

        await ctx.reply(f"```\n" + "\n".join(results) + "\n```")

@bot.command()
async def 오늘의명언(ctx):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  

    url = "https://api.forismatic.com/api/1.0/?method=getQuote&lang=en&format=json"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        quote = data['quoteText']
        author = data['quoteAuthor'] if data['quoteAuthor'] else "Unknown"
        await ctx.reply(f"```오늘의 명언: {quote} - {author}```")
    else:
        await ctx.reply("명언을 가져오는 데 실패했습니다. 다시 시도해 주세요.")

@bot.command()
async def 인스타조회(ctx, username: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if username is None:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}인스타조회 [조회할 유저의 이름]```")  
        return
    try:
        L = instaloader.Instaloader()
        profile = instaloader.Profile.from_username(L.context, username)
        user_info = f"Username: {profile.username}\nFollowers: {profile.followers}\nPosts: {profile.mediacount}\nBio: {profile.biography}"
        await ctx.reply(f'```인스타그램 사용자 정보:\n{user_info}```')
    except Exception as e:
        await ctx.reply(f'```인스타그램 조회 중 오류 발생: {e}```')

@bot.command()
async def 암호화(ctx, key: str = None, *, text: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if key is None or text is None:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}암호화 [AES 128비트 키] [암호화 할 메시지]```")  
        return
    try:
        key = key.encode('utf-8')[:16]  
        cipher = AES.new(key, AES.MODE_ECB) 
        padded_text = pad(text.encode('utf-8'), AES.block_size) 
        encrypted = cipher.encrypt(padded_text)
        encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')  
        await ctx.reply(f'```암호화된 메시지: {encrypted_b64}```')
    except Exception as e:
        await ctx.reply(f'```암호화 중 오류 발생: {e}```')

@bot.command()
async def 복호화(ctx, key: str = None, *, encrypted_text: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if key is None or encrypted_text is None:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}복호화 [AES 128비트 키] [복호화 할 메시지(base64 형식)]```")  
        return
    try:
        key = key.encode('utf-8')[:16] 
        encrypted_text = base64.b64decode(encrypted_text)  

        cipher = AES.new(key, AES.MODE_ECB)  
        decrypted = unpad(cipher.decrypt(encrypted_text), AES.block_size) 
        decrypted_text = decrypted.decode('utf-8') 
        await ctx.reply(f'```복호화된 메시지: {decrypted_text}```')
    except Exception as e:
        await ctx.reply(f'```복호화 중 오류 발생: {e}```')
        
@bot.command()
async def 번역(ctx, lang: str = None, *, text: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if lang is None or text is None:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}번역 [국가 코드 2자리 혹은 나라 이름] [번역할 텍스트]```")  
        return
    try:
        valid_languages = GoogleTranslator().get_supported_languages()
        lang = lang.lower()
        if lang not in valid_languages:
            await ctx.reply(f'```지원되지 않는 언어 코드입니다. 지원되는 언어: {", ".join(valid_languages)}```')
            return
        
        translated = GoogleTranslator(target=lang).translate(text)
        await ctx.reply(f'```번역 결과 ({lang.upper()})\n{translated}```')
    except Exception as e:
        await ctx.reply(f'```번역 중 오류 발생: {e}```')


@bot.command()
async def 유튜브조회(ctx, video_id: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if video_id is None:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}유튜브조회 [조회할 유튜브의 영상 링크 (예시 uUwtnbMW9-c)]```")  
        return
    url = f'https://www.youtube.com/watch?v={video_id}'
    ydl_opts = {"quiet": True}
    
    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        try:
            info = ydl.extract_info(url, download=False)
            title = info.get('title', '제목 없음')
            uploader = info.get('uploader', '업로더 정보 없음')
            views = info.get('view_count', 0)
            likes = info.get('like_count', 0)
            duration = info.get('duration', 0)
            
            response = (f'```제목: {title}\n'
                        f'업로더: {uploader}\n'
                        f'조회수: {views}회\n'
                        f'좋아요: {likes}개\n'
                        f'길이: {duration}초\n'
                        f'링크: {url}```')
            await ctx.reply(response)
        except Exception as e:
            await ctx.reply(f'```유튜브 정보 조회 중 오류 발생: {e}```')




@bot.command()
async def 하입스쿼드(ctx, *args):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    
    if not args:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}하입스쿼드 [1(Bravery) / 2(Brilliance) / 3(Balance)]```")
        return

    valid_numbers = {'1', '2', '3'}
    hype_squad_names = {
        '1': 'Bravery',
        '2': 'Brilliance',
        '3': 'Balance'
    }
    
    for arg in args:
        if arg not in valid_numbers:
            current_prefix = load_prefix()
            await ctx.reply(f"```사용법: {current_prefix}하입스쿼드 [1(Bravery) / 2(Brilliance) / 3(Balance)]```")
            return

    headers = {
        "Authorization": f"{TOKEN}",
        "Content-Type": "application/json"
    }

    for arg in args:
        body = {
            'house_id': f"{arg}"
        }
        response = requests.post(
            'https://discord.com/api/v9/hypesquad/online', headers=headers, json=body
        )

        if response.status_code in [200, 204]:
            house_name = hype_squad_names.get(arg, "알 수 없음")
            await ctx.reply(f"```성공적으로 {house_name} 하우스로 변경되었습니다!```")
        elif response.status_code == 401:
            await ctx.reply("```토큰이 잘못되었거나 만료되었습니다.```")
        elif response.status_code == 429:
            await ctx.reply("```요청이 너무 많습니다. 나중에 다시 시도하세요!```")
        else:
            await ctx.reply(f"```알 수 없는 오류 발생 (상태 코드: {response.status_code})```")
@bot.command()
async def 웹후크생성(ctx, *, name = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return
    if not name:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}웹후크생성 [생성할 웹후크의 이름]```")
        return
    data = {
        "name": name
    }
    headers = {
        "Authorization": f"{TOKEN}",
        "Content-Type": "application/json"
    }
    response = requests.post(
        f"https://discord.com/api/v9/channels/{ctx.channel.id}/webhooks",
        headers=headers,
        json=data
    )

    if response.status_code == 200:
        webhook = response.json()
        await ctx.reply(f"```웹후크가 성공적으로 생성되었습니다!\nURL: {webhook['url']}```")
    else:
        await ctx.reply(f"```웹후크 생성 실패 (상태 코드: {response.status_code})```")
@bot.command()
async def 웹후크삭제(ctx, *, target = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return
    if not target:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}웹후크삭제 [삭제할 웹후크의 이름 또는 웹후크의 URL]```")
        return
    headers = {
        "Authorization": f"{TOKEN}"
    }

    if target.startswith("https://discord.com/api/webhooks/"):
        webhook_id = target.split("/")[5]
        response = requests.delete(
            f"https://discord.com/api/v9/webhooks/{webhook_id}",
            headers=headers
        )
    else:
        response = requests.get(
            f"https://discord.com/api/v9/channels/{ctx.channel.id}/webhooks",
            headers=headers
        )
        if response.status_code == 200:
            webhooks = response.json()
            webhook = next((wh for wh in webhooks if wh["name"] == target), None)
            if webhook:
                response = requests.delete(
                    f"https://discord.com/api/v9/webhooks/{webhook['id']}",
                    headers=headers
                )
            else:
                await ctx.reply("```해당 이름의 웹후크를 찾을 수 없습니다.```")
                return
        else:
            await ctx.reply("```웹후크 정보를 가져오는 데 실패했습니다.```")
            return

    if response.status_code == 204:
        await ctx.reply("```웹후크가 성공적으로 삭제되었습니다!```")
    else:
        await ctx.reply(f"```웹후크 삭제 실패 (상태 코드: {response.status_code})```")
@bot.command()
async def 웹후크전송(ctx, url = None, *, message = None):
    if not url or not message:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}웹후크전송 [웹후크 URL] [전송할 메시지]```")
        return
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return

    webhook_pattern = r"^https:\/\/discord\.com\/api\/webhooks\/\d+\/[\w-]+$"
    if not re.match(webhook_pattern, url):
        await ctx.reply("```올바르지 않은 웹후크 URL입니다.```")
        return

    data = {
        "content": message
    }
    response = requests.post(
        url,
        json=data
    )

    if response.status_code == 204:
        await ctx.reply("```메시지가 성공적으로 전송되었습니다!```")
    else:
        await ctx.reply(f"```메시지 전송 실패 (상태 코드: {response.status_code})```")
@bot.command()
async def 접두사(ctx, *, new_prefix=None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  

    if new_prefix is None:
        
        current_prefix = load_prefix()
        await ctx.reply(f"```현재 접두사는 '{current_prefix}' 입니다.```\n```새로운 접두사를 적용하려면 ' {current_prefix}접두사 \"설정할 접두사\" '를 입력하세요.```")  
    else:
        
        save_prefix(new_prefix)
        bot.command_prefix = new_prefix  
        await ctx.reply(f"```새로운 접두사는 `{new_prefix}` 입니다.```")  


@bot.command()
async def 명령어(ctx):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        print(ctx.author.id)
        print(allowed_users)
        return  

    current_prefix = load_prefix()
    commands_list = '\n'.join([f"{current_prefix}{command.name}" for command in bot.commands if command.name != 'help'])
    
    
    await ctx.reply(f"```사용 가능한 명령어들:\n{commands_list}\n\n🛠️ Developed By nothing._.64```")  


@bot.command()
async def 닉네임변경(ctx, *, new_nickname=None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    
    if new_nickname is None:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}닉네임변경 [변경할 닉네임]```")  
        return

    
    if len(new_nickname) > 32:
        await ctx.reply("```닉네임은 32자 이하로 설정해야 합니다.```")
        return

    
    try:
        await ctx.author.edit(nick=new_nickname)  
        await ctx.reply(f"```닉네임이 변경되었습니다: {new_nickname}```")  
    except selfcord.Forbidden:
        await ctx.reply("```닉네임을 변경할 수 없습니다. 권한이 부족합니다.```")  
    except selfcord.HTTPException as e:
        await ctx.reply(f"```닉네임 변경 중 오류가 발생했습니다: {e}```")


@bot.command()
async def 서버정보(ctx):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    
    guild = ctx.guild  

    
    server_name = guild.name
    server_id = guild.id

    
    created_at = guild.created_at
    created_at_str = created_at.strftime('%Y-%m-%d %H:%M:%S')

    
    member_count = guild.member_count

    
    boost_level = guild.premium_tier

    
    icon_url = guild.icon_url if guild.icon else "아이콘 없음"

    
    text_channels = [channel.name for channel in guild.text_channels]

    
    voice_channels = [channel.name for channel in guild.voice_channels]

    
    roles = [role.name for role in guild.roles]

    
    system_channel = guild.system_channel.name if guild.system_channel else "설정되지 않음"

    
    server_info = (
        f"서버 이름: {server_name}\n"
        f"서버 ID: {server_id}\n"
        f"서버 생성 날짜: {created_at_str}\n"
        f"총 멤버 수: {member_count}\n"
        f"부스트 레벨: {boost_level}\n"
        f"서버 아이콘: {icon_url}\n"
        f"텍스트 채널: {', '.join(text_channels) if text_channels else '없음'}\n"
        f"음성 채널: {', '.join(voice_channels) if voice_channels else '없음'}\n"
        f"역할 목록: {', '.join(roles)}\n"
        f"시스템 메시지 채널: {system_channel}"
    )

    
    await ctx.reply(f"```{server_info}```")

@bot.command()
async def 상태변경(ctx, *, status_message=None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  

    if status_message is None:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}상태변경 [듣는중/시청중/방송중/하는중] [상태 메시지]```")
        return

    if len(status_message) > 100:
        await ctx.reply("```상태 메시지는 100자 이하로 설정해야 합니다.```")
        return

    if "방송중" in status_message:
        config = load_config()
        streamlink = config.get("streaming_link")
        
        link = streamlink  
        status_message = status_message.replace("방송중", "").strip()
        if len(status_message) + len(link) > 100:
            await ctx.reply("상태 메시지와 링크의 길이는 100자 이하이어야 합니다.")
            return
        await bot.change_presence(activity=selfcord.Activity(type=selfcord.ActivityType.streaming, name=status_message, url=link))
        await ctx.reply(f"```상태가 '방송중'으로 변경되었습니다: {status_message} | 링크: {link}```")
        return
    
    if "듣는중" in status_message:
        await bot.change_presence(activity=selfcord.Activity(type=selfcord.ActivityType.listening, name=status_message.replace("듣는중", "").strip()))
        await ctx.reply(f"```상태가 '듣기'로 변경되었습니다: {status_message}```")
        return
    elif "시청중" in status_message:
        await bot.change_presence(activity=selfcord.Activity(type=selfcord.ActivityType.watching, name=status_message.replace("시청중", "").strip()))
        await ctx.reply(f"```상태가 '시청중'으로 변경되었습니다: {status_message}```")
        return
    elif "하는중" in status_message:
        await bot.change_presence(activity=selfcord.Activity(type=selfcord.ActivityType.playing, name=status_message.replace("하는중", "").strip()))
        await ctx.reply(f"```상태가 '하는중'으로 변경되었습니다: {status_message}```")
        return
    else:
        await ctx.reply("```잘못된 상태 타입입니다. '듣는중', '시청중', '방송중', '하는중' 중 하나를 입력해주세요.```")





@bot.command()
async def 도배(ctx, amount: int = None, delay: float = 0, *, message: str = None):

    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if not amount and not message or not delay:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}도배 [횟수] [대기 초] [도배할 메시지]```")
        return

    if amount > 50:
        amount = 50
    elif amount <= 0:
        await ctx.reply("```도배 횟수는 1 이상이어야 합니다.```")
        return

    if not message.strip():
        await ctx.reply("```도배할 텍스트가 없습니다.```")
        return

    for _ in range(amount):
        await ctx.send(message)
        if delay > 0:
            await asyncio.sleep(delay)

    await ctx.reply(f"```현재 채널에 '{message}'를 {amount}번 도배했습니다.```")

@bot.command()
async def 답핑테러(ctx, channel_id: int = None, message_id: int = None, delay: float = 0, amount: int = 1, *, message: str = None):

    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return

    if not channel_id and not message_id and not message or not delay or not amount:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}답핑테러 [채널 ID] [메시지 ID] [대기 초] [횟수] [도배할 메시지]```")
        return

    if amount > 50:
        amount = 50
    elif amount <= 0:
        await ctx.reply("```도배 횟수는 1 이상이어야 합니다.```")
        return

    if not message.strip():
        await ctx.reply("```도배할 텍스트가 없습니다.```")
        return
    try:
        payload = {
            'content': message,
            'tts': False,
            'message_reference': {
                "channel_id": channel_id,
                "message_id": message_id
            }
        }

        sesheaders = headers.copy()
        sesheaders.update({"Authorization": TOKEN})
        session = Client.get_session()
        for _ in range(amount):
            response = session.post(f"https://discord.com/api/v9/channels/{channel_id}/messages", headers=sesheaders, json=payload)
            if response.status_code in [200, 201, 204]:
                pass
            elif response.status_code == 429:
                await ctx.reply(f"```알 수 없는 오류로 답핑 보내기에 실패했습니다. 오류코드 : {response.status_code}```")
                return
            else:
                await ctx.reply(f"```일시적인 제한입니다. 오류코드 : {response.status_code}```")
            if delay > 0:
                await asyncio.sleep(delay)
    except Exception as e:
        await ctx.reply(f"```오류가 발생했습니다. 오류 내용: {e}```")
        return

    await ctx.reply(f"```ID {message_id}에 '{message}'를 {amount}번 답장 핑으로 도배했습니다.```")


@bot.command()
async def 카테고리(ctx, action: str = None, *args):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    
    if not action:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}카테고리 생성 [이름] [개수] 또는 ;카테고리 삭제 [이름/ID]```")
        return
    
    if action == "생성":
        if len(args) != 2:
            await ctx.reply("```카테고리 생성에는 '카테고리 이름'과 '카테고리 수(1~15 자연수)' 두 개의 매개변수가 필요합니다.```")
            return

        category_name = args[0]
        try:
            category_count = int(args[1])
        except ValueError:
            await ctx.reply("```카테고리 수는 1부터 15까지의 자연수여야 합니다.```")
            return

        if not (1 <= category_count <= 15):
            await ctx.reply("```카테고리 수는 1부터 15까지의 자연수여야 합니다.```")
            return

        
        for i in range(category_count):
            await ctx.guild.create_category(category_name)
        await ctx.reply(f"```'{category_name}' 이름의 카테고리 {category_count}개가 생성되었습니다.```")

    
    elif action == "삭제":
        if len(args) != 1:
            await ctx.reply("```카테고리 삭제에는 '카테고리 이름/ID//#카테고리' 매개변수가 필요합니다.```")
            return

        category_info = args[0]

        
        if category_info.startswith("#"):
            
            category_name = category_info[1:]  
            category = selfcord.utils.get(ctx.guild.categories, name=category_name)
        else:
            
            try:
                category = ctx.guild.get_channel(int(category_info))
            except ValueError:
                category = None

        if category:
            await category.delete()
            await ctx.reply(f"```카테고리 '{category.name}'가 삭제되었습니다.```")
        else:
            await ctx.reply("```잘못된 카테고리 이름이나 ID입니다.```")

    else:
        await ctx.reply("```올바른 액션이 아닙니다. '생성' 또는 '삭제'를 사용하세요.```")




@bot.command()
async def 채널(ctx, action: str = None, *args):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    
    if not action:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}채널 생성 [이름] [개수] 또는 ;채널 삭제 [이름/ID]```")
        return

    
    if action == "생성":
        if len(args) != 2:
            await ctx.reply("```채널 생성에는 '채널 이름'과 '채널 수(1~15 자연수)' 두 개의 매개변수가 필요합니다.```")
            return

        channel_name = args[0]
        try:
            channel_count = int(args[1])
        except ValueError:
            await ctx.reply("```채널 수는 1부터 15까지의 자연수여야 합니다.```")
            return

        if not (1 <= channel_count <= 15):
            await ctx.reply("```채널 수는 1부터 15까지의 자연수여야 합니다.```")
            return

        
        for i in range(channel_count):
            await ctx.guild.create_text_channel(channel_name)
        await ctx.reply(f"```'{channel_name}' 이름의 텍스트 채널 {channel_count}개가 생성되었습니다.```")

    
    elif action == "삭제":
        if len(args) != 1:
            await ctx.reply("```채널 삭제에는 '채널 이름/ID/#채널' 매개변수가 필요합니다.```")
            return

        channel_info = args[0]

        
        if channel_info.startswith("#"):
            
            channel_name = channel_info[1:]  
            channel = selfcord.utils.get(ctx.guild.text_channels, name=channel_name)
        else:
            
            try:
                channel = ctx.guild.get_channel(int(channel_info))
            except ValueError:
                channel = None

        if channel:
            await channel.delete()
            await ctx.reply(f"```채널 '{channel.name}'가 삭제되었습니다.```")
        else:
            await ctx.reply("```잘못된 채널 이름이나 ID입니다.```")

    else:
        await ctx.reply("```올바른 액션이 아닙니다. '생성' 또는 '삭제'를 사용하세요.```")



@bot.command()
async def 계좌설정(ctx, billing: str = None, *, name: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    
    if not billing and not name:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}계좌설정 [설정할 계좌] [계좌 주인 이름]```")
        return
    try:
        with open("config.json", "r", encoding="utf-8-sig") as f:
            config_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        config_data = {}

    config_data["billing"] = billing
    config_data["name"] = name

    with open("config.json", "w", encoding="utf-8-sig") as f:
        json.dump(config_data, f, ensure_ascii=False, indent=4)

    await ctx.reply(f"```설정 완료: {billing} - {name}```")

@bot.command()
async def 계좌(ctx):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    try:
        with open("config.json", "r", encoding="utf-8-sig") as f:
            config_data = json.load(f)

        billing = config_data.get("billing", "계좌 정보 없음")
        name = config_data.get("name", "이름 없음")

        await ctx.reply(f"```계좌: {billing}\n이름: {name}```")
    except FileNotFoundError:
        await ctx.reply("```설정된 메시지가 없습니다.```")


@bot.command()
async def 개인청소(ctx, num: int = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  

    if num is None:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}개인청소 [0~99(청소할 수)]```")
        return

    if num < 0 or num > 99:
        await ctx.reply("```청소할 메시지의 개수는 0에서 99 사이여야 합니다.```")
        return

    try:
        deleted_messages = await ctx.channel.purge(limit=num * 1, check=lambda message: message.author == ctx.author)
        deleted_count = min(len(deleted_messages), num)

        await ctx.send(f"```{deleted_count}개의 메시지를 청소했습니다.```")
    except selfcord.Forbidden:
        await ctx.reply("```메시지를 삭제할 권한이 없습니다.```")
    except selfcord.HTTPException as e:
        await ctx.reply(f"```메시지 삭제 중 오류가 발생했습니다: {e}```")

@bot.command()
async def 유저차단(ctx, user: str = None):
    if not user:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}유저차단 [유저 멘션 혹은 유저 ID]```")
        return

    match = re.match(r"<@!?(\d+)>", user)
    if match:
        user_id = match.group(1)
    else:
        user_id = user

    sesheaders = headers.copy()
    sesheaders.update({"Authorization": TOKEN})

    url = f"https://discord.com/api/v9/users/@me/relationships/{user_id}"
    payload = {"type": 2}

    response = requests.put(url, headers=sesheaders, json=payload)

    if response.status_code in [200, 204]:
        await ctx.reply(f"```유저(ID: {user_id})를 성공적으로 차단했습니다.```")
    else:
        await ctx.reply(f"```유저 차단 실패. 오류 코드: {response.status_code}, 응답: {response.text}```")

@bot.command()
async def 친구추가(ctx, user: str = None):
    if not user:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}친구추가 [유저 멘션 혹은 유저 ID]```")
        return

    match = re.match(r"<@!?(\d+)>", user)
    if match:
        user_id = match.group(1)
    else:
        user_id = user

    sesheaders = headers.copy()
    sesheaders.update({"Authorization": TOKEN})

    url = "https://discord.com/api/v9/users/@me/relationships"
    payload = {"username": user_id}

    response = requests.post(url, headers=sesheaders, json=payload)

    if response.status_code in [200, 204]:
        await ctx.reply(f"```유저(ID: {user_id})에게 친구 요청을 보냈습니다.```")
    else:
        await ctx.reply(f"```친구 요청 실패. 오류 코드: {response.status_code}, 응답: {response.text}```")

@bot.command()
async def 유저차단해제(ctx, user: str = None):
    if not user:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}유저차단해제 [유저 멘션 혹은 유저 ID]```")
        return

    match = re.match(r"<@!?(\d+)>", user)
    if match:
        user_id = match.group(1)
    else:
        user_id = user

    sesheaders = headers.copy()
    sesheaders.update({"Authorization": TOKEN})

    url = f"https://discord.com/api/v9/users/@me/relationships/{user_id}"

    response = requests.delete(url, headers=sesheaders)

    if response.status_code in [200, 204]:
        await ctx.reply(f"```유저(ID: {user_id})의 차단을 해제했습니다.```")
    else:
        await ctx.reply(f"```유저 차단 해제 실패. 오류 코드: {response.status_code}, 응답: {response.text}```")


@bot.command()
async def 타임아웃(ctx, time_unit: str = None, time_value: int = None, member: selfcord.Member = None, *, reason: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    
    if not time_unit or not time_value or not member:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}타임아웃 [초/분/시간/일] [시간] [@유저] [사유(선택)]```")
        return
    
    if time_unit not in ["초", "분", "시간", "일"]:
        await ctx.reply("```시간 단위는 '초', '분', '시간', '일' 중 하나여야 합니다.```")
        return
    
    if time_value <= 0:
        await ctx.reply("```시간은 1 이상이어야 합니다.```")
        return

    
    timeout_duration = 0
    if time_unit == "초":
        timeout_duration = time_value
    elif time_unit == "분":
        timeout_duration = time_value * 60
    elif time_unit == "시간":
        timeout_duration = time_value * 3600
    elif time_unit == "일":
        timeout_duration = time_value * 86400

    
    max_timeout = 28 * 86400
    if timeout_duration > max_timeout:
        timeout_duration = max_timeout

    
    timeout_duration = timedelta(seconds=timeout_duration)

    
    timeout_time = datetime.utcnow() + timeout_duration

    
    timeout_iso = timeout_time.isoformat()

    
    url = f"https://discord.com/api/v9/guilds/{ctx.guild.id}/members/{member.id}"

    
    timeout_data = {
        "communication_disabled_until": timeout_iso,
        "reason": reason
    }

    
    headers = {
        "Authorization": f"{TOKEN}",
        "Content-Type": "application/json"
    }
    try:
        
        response = requests.patch(url, json=timeout_data, headers=headers)

        
        if response.status_code == 200:
            await ctx.reply(f"```{member.mention} 님이 타임아웃되었습니다. 이유: {reason if reason else '없음'}```")
        elif response.status_code == 403:
            await ctx.reply("```타임아웃 권한이 없습니다. 유저의 역할이 대상보다 높은지 확인하세요.```")
        elif response.status_code == 404:
            await ctx.reply("```유효하지 않은 유저입니다.```")
        else:
            await ctx.reply(f"```타임아웃을 설정할 수 없습니다. 오류 코드: {response.status_code}```")
    except requests.exceptions.RequestException as e:
        await ctx.reply(f"```타임아웃 요청 중 오류 발생: {e}```")
    except selfcord.Forbidden:
        await ctx.reply("```유저에게 타임아웃 권한이 없습니다.```")
    except selfcord.HTTPException:
        await ctx.reply("```타임아웃 설정 중 오류가 발생했습니다.```")
@bot.command()
async def 타임아웃해제(ctx, user: selfcord.Member, *, reason=None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if not user:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}타임아웃해제 [@유저] [사유(선택)]```")
        return
    url = f"https://discord.com/api/v9/guilds/{ctx.guild.id}/members/{user.id}"
    headers = {
        "Authorization": f"{TOKEN}",
        "Content-Type": "application/json"
    }


    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        member_data = response.json()

        if member_data.get("communication_disabled_until"):
            payload = {
                "communication_disabled_until": None
            }
            response = requests.patch(url, headers=headers, json=payload)

            if response.status_code == 200:
                if reason:
                    await ctx.reply(f"```{user.name}의 타임아웃이 해제되었습니다. 사유: {reason}```")
                else:
                    await ctx.reply(f"```{user.name}의 타임아웃이 해제되었습니다.```")
            else:
                await ctx.reply(f"```타임아웃 해제에 실패했습니다. 오류: {response.status_code}```")
        else:
            await ctx.reply(f"```{user.name}는 현재 타임아웃 상태가 아닙니다.```")
    else:
        await ctx.reply(f"```유저 정보 조회에 실패했습니다. 오류: {response.status_code}```")


@bot.command()
async def IP조회(ctx, ip_address: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return

    if not ip_address:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}IP조회 [IPv4 또는 IPv6 주소]```")
        return

    if not (IPV4_PATTERN.match(ip_address) or IPV6_PATTERN.match(ip_address)):
        await ctx.reply("```유효한 IP 주소 형식이 아닙니다. IPv4 또는 IPv6 주소를 입력하세요.```")
        return

    if any(ip_address.startswith(private) for private in PRIVATE_IP_RANGES):
        await ctx.reply("```비공개(내부) IP 주소는 조회할 수 없습니다.```")
        return

    url = f"http://ipinfo.io/{ip_address}/json"

    try:
        response = requests.get(url, timeout=5)
        data = response.json()

        if response.status_code == 200:
            ip_info = data.get('ip', '정보 없음')
            city = data.get('city', '정보 없음')
            region = data.get('region', '정보 없음')
            country = data.get('country', '정보 없음')
            loc = data.get('loc', '정보 없음')
            org = data.get('org', '정보 없음')

            result = (f"IP 주소: {ip_info}\n"
                      f"도시: {city}\n"
                      f"지역: {region}\n"
                      f"국가: {country}\n"
                      f"위치 (위도, 경도): {loc}\n"
                      f"ISP: {org}")

            await ctx.reply(f"```{result}```")
        else:
            await ctx.reply("```IP 정보 조회에 실패했습니다. 올바른 IP 주소를 입력하세요.```")

    except requests.exceptions.Timeout:
        await ctx.reply("```IP 정보 조회 요청이 시간 초과되었습니다. 나중에 다시 시도하세요.```")
    except requests.exceptions.RequestException as e:
        await ctx.reply(f"```IP 정보 조회 중 오류가 발생했습니다: {e}```")
@bot.command()
async def 접속환경조회(ctx):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    
    system_info = platform.system()  
    version_info = platform.version()  
    architecture = platform.architecture()  
    processor = platform.processor()  

    
    result = (f"```운영 체제: {system_info} {version_info}\n"
              f"시스템 아키텍처: {architecture[0]}\n"
              f"프로세서: {processor}```")
    
    await ctx.reply(result)


@bot.command()
async def 추방(ctx, member: selfcord.Member = None, *, reason=None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  

    if not member:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}추방 [유저] [사유(선택)]```")
        return
    
    if reason is None:
        reason = "명시된 이유 없음"
    if member == ctx.author:
        await ctx.reply("```자기 자신을 추방할 수 없습니다.```")
        return

    if member == ctx.guild.owner:
        await ctx.reply("```서버 소유자는 추방할 수 없습니다.```")
        return

    if member.top_role >= ctx.author.top_role:
        await ctx.reply("```자신보다 높은 역할을 가진 유저는 추방할 수 없습니다.```")
        return



    try:
        
        await member.kick(reason=reason)
        await ctx.reply(f"```{member}님을 추방했습니다. 이유: {reason}```")
    except selfcord.Forbidden:
        await ctx.reply("```이 유저를 추방할 권한이 없습니다.```")
    except selfcord.HTTPException:
        await ctx.reply("```추방에 실패했습니다.```")


@bot.command()
async def 밴(ctx, member: selfcord.Member = None, *, reason=None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if not member:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}밴 [유저] [사유(선택)]```")
        return
    
    if reason is None:
        reason = "명시된 이유 없음"

    if member == ctx.author:
        await ctx.reply("```자기 자신을 밴할 수 없습니다.```")
        return

    if member == ctx.guild.owner:
        await ctx.reply("```서버 소유자는 밴할 수 없습니다.```")
        return

    if member.top_role >= ctx.author.top_role:
        await ctx.reply("```자신보다 높은 역할을 가진 유저는 밴할 수 없습니다.```")
        return



    try:
        
        await member.ban(reason=reason)
        await ctx.reply(f"```{member}님을 밴했습니다. 이유: {reason}```")
    except selfcord.Forbidden:
        await ctx.reply("```이 유저를 밴할 권한이 없습니다.```")
    except selfcord.HTTPException:
        await ctx.reply("```밴에 실패했습니다.```")

@bot.command()
async def 언밴(ctx, user_id: int = None, *, reason=None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    guild_id = ctx.guild.id
    headers = {
        "Authorization": f"{TOKEN}",
        "Content-Type": "application/json"
    }

    if user_id is None:
        try:
            response = requests.get(
                f"https://discord.com/api/v9/guilds/{guild_id}/bans",
                headers=headers
            )

            if response.status_code != 200:
                await ctx.reply(f"```밴 리스트를 가져올 수 없습니다. 오류 코드: {response.status_code}```")
                return

            bans = response.json()
            if not bans:
                await ctx.reply("```현재 밴된 유저가 없습니다.```")
                return

            message = ""
            for ban_entry in bans:
                user = ban_entry["user"]
                message += f"{user['username']} - ID: {user['id']}\n"
            current_prefix = load_prefix()
            await ctx.reply(f"**밴된 유저 목록:**\n```{message}\n\n유저를 언밴하고 싶다면 {current_prefix}언밴 [유저 ID] [사유(선택사항)] 을 입력하세요.```")

        except Exception as e:
            await ctx.reply(f"```오류가 발생했습니다: {e}```")

    else:
        try:
            url = f"https://discord.com/api/v9/guilds/{guild_id}/bans/{user_id}"
            payload = {"reason": reason} if reason else {}

            response = requests.delete(url, headers=headers, json=payload)

            if response.status_code == 204:
                await ctx.reply(f"```ID: {user_id}의 밴이 해제되었습니다." + (f" 사유: {reason}" if reason else "" + "```"))
            elif response.status_code == 404:
                await ctx.reply("```해당 ID의 유저가 밴 리스트에 없습니다.```")
            else:
                await ctx.reply(f"```밴 해제에 실패했습니다. 오류 코드: {response.status_code}```")

        except Exception as e:
            await ctx.reply(f"```오류가 발생했습니다: {e}```")


@bot.command()
async def 슬로우모드(ctx, time_unit: str = None, time_value: int = None, apply_to_all: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    
    if not time_unit or time_value is None or not apply_to_all:
        current_prefix = load_prefix() 
        await ctx.reply(f"```사용법: {current_prefix}슬로우모드 [초/분/시/일] [시간] [예/아니오(모든 채널에 적용 여부)]```")
        return
    if time_value <= 0:
        await ctx.reply("```슬로우모드 시간은 1 이상이어야 합니다.```")
        return
    
    time_in_seconds = 0
    if time_unit == "초":
        time_in_seconds = time_value
    elif time_unit == "분":
        time_in_seconds = time_value * 60
    elif time_unit == "시":
        time_in_seconds = time_value * 3600
    elif time_unit == "일":
        time_in_seconds = time_value * 86400
    else:
        await ctx.reply("```잘못된 시간 단위입니다. '초', '분', '시', '일' 중 하나를 선택해주세요.```")
        return

    
    if apply_to_all.lower() == "예":
        for channel in ctx.guild.text_channels:
            try:
                await channel.edit(slowmode_delay=time_in_seconds)
            except selfcord.Forbidden:
                await ctx.reply(f"```{channel.name} 채널에 대해 슬로우모드를 설정할 권한이 없습니다.```")
            except selfcord.HTTPException:
                await ctx.reply(f"```{channel.name} 채널에 대한 슬로우모드 적용에 실패했습니다.```")
        await ctx.reply(f"```모든 채널에 슬로우모드 {time_value} {time_unit}(으)로 설정되었습니다.```")
    elif apply_to_all.lower() == "아니오":
        try:
            await ctx.channel.edit(slowmode_delay=time_in_seconds)
            await ctx.reply(f"```현재 채널에 슬로우모드 {time_value} {time_unit}(으)로 설정되었습니다.```")
        except selfcord.Forbidden:
            await ctx.reply("```이 채널에 대해 슬로우모드를 설정할 권한이 없습니다.```")
        except selfcord.HTTPException:
            await ctx.reply("```슬로우모드 설정에 실패했습니다.```")
    else:
        await ctx.reply("```'모든 채널 여부'는 '예' 또는 '아니오'만 가능합니다.```")


@bot.command()
async def 대명사변경(ctx, *, pronouns: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return 

    if pronouns is None:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}대명사변경 [대명사]```")
        return

    if len(pronouns) == 0:
        await ctx.reply("```대명사는 최소 1자 이상이어야 합니다.```")
        return
    if len(pronouns) > 190:
        await ctx.reply("```대명사는 최대 190자까지만 가능합니다.```")
        return
    await ctx.reply(f"```대명사를 '{pronouns}'으로 설정합니다...```")

    
    payload = {
        "pronouns": pronouns
    }

    sesheaders = headers.copy()
    sesheaders.update({'Authorization': TOKEN})

    response = requests.patch("https://discord.com/api/v9/users/@me/profile", headers=sesheaders, json=payload)
        
    if response.status_code == 200:
        await ctx.reply("```대명사 변경이 완료되었습니다!```")
    elif response.status_code == 403:
        await ctx.reply("```대명사를 변경할 권한이 없습니다.```")
    elif response.status_code == 400:
        await ctx.reply("```잘못된 입력값입니다. 다시 확인해주세요.```")
    elif response.status_code == 429:
        await ctx.reply("```너무 많은 요청을 보냈습니다. 잠시 후 다시 시도해주세요.```")
    else:
        await ctx.reply(f"```대명사 변경 중 오류 발생: {response.status_code}```")




@bot.command()
async def 설명변경(ctx, *, bio: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if bio is None:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}설명변경 [설명 내용]```")
        return
    if len(bio) == 0:
        await ctx.reply("```설명은 최소 1자 이상이어야 합니다.```")
        return
    if len(bio) > 190:
        await ctx.reply("```설명은 최대 190자까지만 가능합니다.```")
        return
    await ctx.reply(f"```설명을 '{bio}'로 설정합니다...```")

    
    payload = {
        "bio": bio
    }

    sesheaders = headers.copy()
    sesheaders.update({'Authorization': TOKEN})

    response = requests.patch("https://discord.com/api/v9/users/@me/profile", headers=sesheaders, json=payload)
        
    if response.status_code == 200:
        await ctx.reply("```설명 변경이 완료되었습니다!```")
    elif response.status_code == 403:
        await ctx.reply("```설명을 변경할 권한이 없습니다.```")
    elif response.status_code == 400:
        await ctx.reply("```잘못된 입력값입니다. 다시 확인해주세요.```")
    elif response.status_code == 429:
        await ctx.reply("```너무 많은 요청을 보냈습니다. 잠시 후 다시 시도해주세요.```")
    else:
        await ctx.reply(f"```설명 변경 중 오류 발생: {response.status_code}```")

@bot.command()
async def 토큰조회(ctx, *, token: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return 

    if not token:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}토큰조회 [조회할 토큰]```")
        return
    sesheaders = headers.copy()
    sesheaders.update({"Authorization": token})

    try:
        r = requests.get('https://discord.com/api/v9/users/@me', headers=sesheaders)
        if r.status_code == 200:
            await ctx.reply("```조회 가능 토큰입니다. 잠시만 기다려주세요...```")
        elif r.status_code == 403:
            await ctx.reply(f"```조회 불가 토큰입니다. 잠긴 토큰입니다. 오류 코드 : {r.status_code}```")
            return
        elif r.status_code == 401:
            await ctx.reply(f"```조회 불가 토큰입니다. 올바르지 않은 토큰입니다. 오류 코드 : {r.status_code}```")
            return
        else:
            await ctx.reply(f"```일시적인 오류입니다. 잠시 기다려주십시오. 오류 코드 : {r.status_code}```")
            return
        badges = ""
        discord_Employee = 1
        Partnered_Server_Owner = 2
        HypeSquad_Events = 4
        Bug_Hunter_Level_1 = 8
        House_Bravery = 64
        House_Brilliance = 128
        House_Balance = 256
        Early_Supporter = 512
        Bug_Hunter_Level_2 = 16384
        Early_Verified_Bot_Developer = 131072

        flags = r.json()['flags']
        if (flags == discord_Employee):
            badges += "Staff, "
        if (flags == Partnered_Server_Owner):
            badges += "Partner, "
        if (flags == HypeSquad_Events):
            badges += "Hypesquad Event, "
        if (flags == Bug_Hunter_Level_1):
            badges += "Green Bughunter, "
        if (flags == House_Bravery):
            badges += "Bravery, "
        if (flags == House_Brilliance):
            badges += "Brillance, "
        if (flags == House_Balance):
            badges += "Balance, "
        if (flags == Early_Supporter):
            badges += "Early Supporter, "
        if (flags == Bug_Hunter_Level_2):
            badges += "Gold BugHunter, "
        if (flags == Early_Verified_Bot_Developer):
            badges += "Verified Bot Developer, "
        if (flags == Early_Verified_Bot_Developer):
            badges += "Verified Bot Developer, "
        if (badges == ""):
            badges = "None"

        userName = r.json()['username'] + '#' + r.json()['discriminator']
        userID = r.json()['id']
        phone = r.json()['phone']
        email = r.json()['email']
        mfa = r.json()['mfa_enabled']
        avatar_id = r.json()['avatar']
        has_nitro = False
        res = requests.get('https://discordapp.com/api/v9/users/@me/billing/subscriptions', headers=sesheaders)
        nitro_data = res.json()
        has_nitro = bool(len(nitro_data) > 0)

        if has_nitro:
            from datetime import datetime
            d1 = datetime.strptime(nitro_data[0]["current_period_end"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
            d2 = datetime.strptime(nitro_data[0]["current_period_start"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
            days_left = abs((d2 - d1).days)

        
        token_info = (
            f"토큰: {token[:27]}\n"
            f"유저 이름: {userName}\n"
            f"유저 ID: {userID}\n"
            f"이메일: {email}\n"
            f"전화번호 {phone}\n"
            f"2단계 인증: {mfa}\n"
            f"니트로 여부: {has_nitro} / {days_left if has_nitro else '0'} days\n"
            f"배지: {badges}\n"
            f"\n✅ 토큰을 성공적으로 조회했습니다!"
            f"\n\n"
            f"🛠️ Developed by nothing._.64"
        )
        await ctx.reply(f"```{token_info}```")
    except Exception as e:
        await ctx.reply(f"토큰 조회중 오류가 발생했습니다! 오류 내용: {e}")
        return


@bot.command()
async def 주사위(ctx, start: str = None, end: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  

    if start is None or end is None:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}주사위 [시작수] [끝수]```")
        return

    
    if not start.isdigit() or not end.isdigit():
        await ctx.reply("```오류: 시작수와 끝수는 숫자로 입력해야 합니다.```")
        return

    start, end = int(start), int(end)

    
    if start >= end:
        await ctx.reply("```오류: 시작수는 끝수보다 작아야 합니다.```")
        return

    
    result = random.randint(start, end)
    await ctx.reply(f"```🎲 주사위 결과: {result} (범위: {start}~{end})```")



@bot.command()
async def 역할(ctx, action: str = None, role_name: str = None, amount: int = 1):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  

    
    if action not in ["생성", "제거"] or role_name is None:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}역할 생성 [역할이름] [생성할 개수)] 또는 {current_prefix}역할 제거 [역할 이름(또는 역할 ID)]```")
        return

    
    if action == "생성":
        if not (1 <= amount <= 10):  
            await ctx.reply("```1~10개 사이로 역할을 생성할 수 있습니다.```")
            return

        created_roles = []
        for i in range(amount):
            try:
                role = await ctx.guild.create_role(name=role_name)
                created_roles.append(role.name)
            except selfcord.Forbidden:
                await ctx.reply("```역할을 생성할 권한이 없습니다.```")
                return
            except selfcord.HTTPException:
                await ctx.reply("```역할 생성에 실패했습니다.```")
                return

        await ctx.reply(f"```'{', '.join(created_roles)}' 역할이 {amount}개 생성되었습니다.```")

    
    elif action == "제거":
        role = None

        
        role = selfcord.utils.get(ctx.guild.roles, name=role_name)
        
        
        if role is None and role_name.isdigit():
            role = ctx.guild.get_role(int(role_name))

        if role:
            try:
                await role.delete()
                await ctx.reply(f"```'{role.name}' 역할이 삭제되었습니다.```")
            except selfcord.Forbidden:
                await ctx.reply("```이 역할을 삭제할 권한이 없습니다.```")
            except selfcord.HTTPException:
                await ctx.reply("```역할 삭제에 실패했습니다.```")
        else:
            await ctx.reply("```해당 역할을 찾을 수 없습니다. 역할 이름 또는 ID를 확인하세요.```")

    else:
        await ctx.reply("```올바른 액션이 아닙니다. '생성' 또는 '제거'를 사용하세요.```")

@bot.command()
async def 서버복제(ctx, source_guild_id: int = None, target_guild_id: int = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return
    source_guild = bot.get_guild(source_guild_id)
    target_guild = bot.get_guild(target_guild_id)

    if not source_guild or not target_guild:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}서버복제 [원본 서버 ID] [복제할 서버 ID]```")
        return

    if not target_guild.me.guild_permissions.administrator:
        await ctx.reply("```복사될 서버에서 관리자 권한이 필요합니다.```")
        return

    await ctx.reply(f"```'{source_guild.name}' 서버를 '{target_guild.name}' 서버로 복제합니다.```")

    role_map = {}

    for role in source_guild.roles:
        if role.name == "@everyone":
            continue

        new_role = await target_guild.create_role(
            name=role.name,
            color=role.color,
            hoist=role.hoist,
            mentionable=role.mentionable,
            permissions=role.permissions 
        )
        role_map[role.id] = new_role
        await asyncio.sleep(1)

    channel_map = {}

    for category in source_guild.categories:
        new_category = await target_guild.create_category(category.name, position=category.position)
        channel_map[category.id] = new_category

        for overwrite_target, overwrite in category.overwrites.items():
            target = role_map.get(overwrite_target.id) or target_guild.get_member(overwrite_target.id)
            if target:
                await new_category.set_permissions(target, overwrite=overwrite)

        await asyncio.sleep(1)

    for channel in source_guild.channels:
        if isinstance(channel, selfcord.TextChannel):
            new_channel = await target_guild.create_text_channel(channel.name, category=channel_map.get(channel.category_id))
        elif isinstance(channel, selfcord.VoiceChannel):
            new_channel = await target_guild.create_voice_channel(channel.name, category=channel_map.get(channel.category_id))
        else:
            continue

        channel_map[channel.id] = new_channel

        for overwrite_target, overwrite in channel.overwrites.items():
            target = role_map.get(overwrite_target.id) or target_guild.get_member(overwrite_target.id)
            if target:
                await new_channel.set_permissions(target, overwrite=overwrite)

        await asyncio.sleep(1)

    for emoji in source_guild.emojis:
        emoji_bytes = await emoji.url.read()
        await target_guild.create_custom_emoji(name=emoji.name, image=emoji_bytes)
        await asyncio.sleep(2)

    await ctx.reply("```서버 복제가 완료되었습니다!```")


@bot.command()
async def 유저파싱(ctx, user: selfcord.Member = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return  
    if not user:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법 : {current_prefix}유저파싱 [파싱할 유저]```")
    
    user_info = {
        "아이디": user.id,
        "이름": user.name,
        "태그": user.discriminator,
        "멘션": user.mention,
        "서버 참가일": str(user.joined_at),
        "상태": str(user.status),
        "활동": str(user.activity) if user.activity else "활동 없음",
        "역할": [role.name for role in user.roles],
        "프로필 사진": user.avatar_url
    }
    
    
    user_info_str = "\n".join([f"{key}: {value}" for key, value in user_info.items()])

    
    if len(user_info_str) > 2000:
        
        parts = [user_info_str[i:i+2000] for i in range(0, len(user_info_str), 2000)]
        for part in parts:
            await ctx.reply(part)
    else:
        
        await ctx.reply(f"파싱된 유저 정보:\n```{user_info_str}```")

@bot.command()
async def 고르기(ctx, *choices):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return
    if not choices:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}고르기 [선택지 1] [선택지 2] [...선택지 50]```")
        return
    if len(choices) < 2:
        await ctx.reply("```최소 2개 이상의 선택지를 추가하세요.```")
        return
    
    selected = random.choice(choices)  
    await ctx.reply(f"```🎲 선택 결과: {selected}```")






@bot.command()
async def 웹사이트조회(ctx, url: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return
    if not url:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}웹사이트조회 [조회할 웹사이트]```")
        return

    
    if not url.startswith("http"):
        url = "https://" + url

    
    try:
        
        hostname = url.split("://")[1].split("/")[0]
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror:
        await ctx.reply(f"❌ IP 정보를 가져올 수 없습니다. `{url}`이 유효하지 않은 웹사이트일 수 있습니다.")
        return

    
    ipinfo_url = f"https://ipinfo.io/{ip_address}/json"
    try:
        ipinfo_response = requests.get(ipinfo_url)
        ipinfo_data = ipinfo_response.json()
    except RequestException:
        await ctx.reply(f"❌ 웹사이트 정보 요청에 실패했습니다. `{url}`을(를) 확인할 수 없습니다.")
        return

    
    try:
        cert_url = f"https://www.ssllabs.com/ssltest/analyze.html?d={hostname}"
        cert_info = f"🔒 인증서 확인: [SSL Labs 분석 링크]({cert_url})"
    except Exception as e:
        cert_info = f"🔒 인증서 정보 확인 중 오류 발생: {str(e)}"

    
    try:
        response = requests.get(url, timeout=5)
        status_code = response.status_code

        if status_code == 200:
            status_message = f"✅ 웹사이트가 정상적으로 운영 중입니다! (응답 코드: {status_code})"
        else:
            status_message = f"❌ 웹사이트가 다운되었거나 응답 코드: {status_code}이 반환되었습니다."
    except RequestException:
        status_message = "❌ 웹사이트가 다운되었습니다."

    
    result_message = f"""
    🔍 웹사이트 정보:
    - URL: {url}
    - IP 주소: {ip_address}
    - 위치: {ipinfo_data.get('city', '알 수 없음')}, {ipinfo_data.get('country', '알 수 없음')}
    - {cert_info}
    - {status_message}
    """
    await ctx.reply(f"```{result_message}```")
@bot.command()
async def DM전송(ctx, user: selfcord.User = None, *, message: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return
    if not user and not message:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}DM전송 [DM을 전송할 유저] [전송할 메시지]```")
        return
    try:
        
        await user.send(message)
        await ctx.reply(f"```{user.name}에게 DM을 성공적으로 전송했습니다.```")
    except selfcord.Forbidden:
        
        await ctx.reply(f"```{user.name}는 DM을 받을 수 없습니다.```")
    except Exception as e:
        
        await ctx.reply(f"```오류가 발생했습니다: {str(e)}```")


@bot.command()
async def 계산(ctx, *, expression: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return
    if not expression:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법 : {current_prefix}계산 [계산할 식]```")
        return
    try:
        expression = expression.replace("^", "**")

        expression = re.sub(r'(\d+)!', r'math.factorial(\1)', expression)

        expression = re.sub(r'math\.pi(!)', r'math.pi', expression)

        if '**' in expression:
            base, exponent = expression.split("**")
            base = int(base) if base.isdigit() else 0
            exponent = int(exponent) if exponent.isdigit() else 0
            if exponent > 1000: 
                await ctx.reply("```계산이 너무 큽니다. 작은 수로 시도해 주세요.```")
                return

        result = eval(expression, {"__builtins__": None}, {"math": math})
        await ctx.reply(f"```계산 결과: {result}```")
        
    except Exception as e:
        await ctx.reply(f"```계산 오류: {str(e)}```")

@bot.command()
async def 핑(ctx):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return
    latency = round(bot.latency * 1000)  
    await ctx.reply(f"```현재 핑은 {latency}ms 입니다.```")
@bot.command()
async def 서버채팅락다운(ctx):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return
    
    await ctx.guild.default_role.edit(permissions=selfcord.Permissions(send_messages=False))
    
    await ctx.reply("```채팅 락다운이 활성화되었습니다. 모든 유저가 메시지를 보낼 수 없습니다.```")

@bot.command()
async def 서버채팅락다운해제(ctx):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return
    
    await ctx.guild.default_role.edit(permissions=selfcord.Permissions(send_messages=True))
    
    await ctx.reply("```채팅 락다운이 해제되었습니다. 모든 유저가 메시지를 보낼 수 있습니다.```")

@bot.command()
async def 디데이계산(ctx, target_date: str = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return

    if not target_date:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법 : {current_prefix}디데이계산 [YYYY-MM-DD 형식 (Y=year, M=month, D=day)]```")
        return
    
    try:
        
        kst = pytz.timezone('Asia/Seoul')

        
        target_date_obj = datetime.strptime(target_date, '%Y-%m-%d')
        target_date_obj = kst.localize(target_date_obj)

        
        current_time = datetime.now(kst)

        
        delta = target_date_obj - current_time
        years = delta.days // 365
        months = (delta.days % 365) // 30
        days = (delta.days % 365) % 30
        hours = delta.seconds // 3600
        minutes = (delta.seconds % 3600) // 60
        seconds = delta.seconds % 60

        await ctx.reply(f"```디데이 계산 결과:\n"
                         f"{target_date}까지 남은 시간:\n"
                         f"{years}년 {months}개월 {days}일 {hours}시간 {minutes}분 {seconds}초```")

    except Exception as e:
        await ctx.reply(f"```에러가 발생했습니다: {str(e)}```")


@bot.command()
async def 반복도배(ctx, channel_id: int = None, delay: float = None, *, message: str = None):
    global spamming_task  

    if not channel_id or not delay or not message:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}반복도배 [채널 ID] [대기시간] [메시지]```")
        return

    if delay < 5:
        await ctx.reply("```대기 시간은 최소 5초 이상이어야 합니다.```")
        return

    if spamming_task:
        spamming_task.cancel()
        await ctx.reply("```기존 반복 도배를 종료하고 새로운 도배를 시작합니다.```")

    sesheaders = headers.copy()
    sesheaders.update({"Authorization": TOKEN})
    url = f"https://discord.com/api/v9/channels/{channel_id}/messages"

    async def spam_task():
        while True:
            payload = {"content": message}
            response = requests.post(url, headers=sesheaders, json=payload)

            if response.status_code not in [200, 201]:
                await ctx.reply(f"```[디버그 메시지] 메시지 전송 실패. 오류 코드: {response.status_code}, 응답: {response.text}```")
                break  

            await asyncio.sleep(delay)

    spamming_task = asyncio.create_task(spam_task()) 
    await ctx.reply(f"```채널(ID: {channel_id})에서 {delay}초 간격으로 반복 도배를 시작합니다.```")


@bot.command()
async def 반복도배종료(ctx):
    global spamming_task

    if spamming_task:
        spamming_task.cancel()  
        spamming_task = None 
        await ctx.reply("```반복 도배를 중지했습니다.```")
    else:
        await ctx.reply("```현재 실행 중인 반복 도배가 없습니다.```")



@bot.command()
async def 스레드도배(ctx, thread_id: int = None, count: int = None, delay: float = 0, *, message: str = None):
    if not thread_id or not count or not message or not delay:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}스레드도배 [스레드 ID] [보낼 횟수] [대기 초] [보낼 메시지]```")
        return

    if count > 50:
        await ctx.reply("```보낼 횟수는 최대 50번까지 가능합니다.```")
        return

    sesheaders = headers.copy()
    sesheaders.update({"Authorization": TOKEN})

    url = f"https://discord.com/api/v9/channels/{thread_id}/messages"

    for i in range(count):
        payload = {"content": message}
        response = requests.post(url, headers=sesheaders, json=payload)

        if response.status_code == 200 or response.status_code == 201:
            pass
        else:
            await ctx.reply(f"```[{i+1}/{count}] 메시지 전송 실패. 오류 코드: {response.status_code}, 응답: {response.text}```")
            break 
        if delay > 0:
            await asyncio.sleep(delay)

    await ctx.reply(f"```스레드({thread_id})에 {count}번의 메시지를 전송했습니다.```")

@bot.command()
async def 정보(ctx, user: selfcord.Member = None):
    allowed_users = load_allowed_users()
    if str(ctx.author.id) not in allowed_users:
        return

    
    bot_name = bot.user.name
    bot_id = bot.user.id
    server_count = len(bot.guilds)  
    command_count = len(bot.commands)  
    if user:  
        user_name = user.name
        user_id = user.id
        user_status = user.status
        user_joined = user.joined_at.strftime("%Y-%m-%d %H:%M:%S")  
        response = ""
        
        response += f"```\n\n유저 정보:\n"
        response += f"유저 이름: {user_name}\n"
        response += f"유저 아이디: {user_id}\n"
        response += f"상태: {user_status}\n"
        response += f"서버 가입 날짜: {user_joined}\n"
        response += "```"
    else:
        response = f"""```
        이름: {bot_name}
        아이디: {bot_id}
        서버 수: {server_count}
        명령어 수: {command_count}
        상태: 활성 상태
        라이브러리 버전: {LIB_VER}
        클라이언트 버전: {LOCAL_VER}
        오픈소스 프로젝트 링크 : https://github.com/Nothing-64/SelfBot-Main
        ```"""


    
    await ctx.reply(response)


@bot.command()
async def 위도경도조회(ctx, latitude: float = None, longitude: float = None):
    if latitude is None or longitude is None:
        current_prefix = load_prefix()
        await ctx.reply(f"```사용법: {current_prefix}위도경도조회 [위도] [경도]```")
        return
    
    url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={latitude}&lon={longitude}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SelfBot/1.0"
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if "display_name" in data:
                await ctx.reply(f"```해당 좌표의 위치: {data['display_name']}```")
            else:
                await ctx.reply("```위치 정보를 찾을 수 없습니다.```")
        else:
            await ctx.reply(f"```위도경도 조회 실패. 오류 코드: {response.status_code}```")
    except Exception as e:
        await ctx.reply(f"```오류 발생: {str(e)}```")


@bot.event
async def on_ready():
    bot.command_prefix = load_prefix()  
    print(f"Logged in as {bot.user}!")
@bot.event
async def on_command_error(ctx, error):
    
    if isinstance(error, commands.CommandNotFound):
        pass  

bot.run(TOKEN, bot = False)
