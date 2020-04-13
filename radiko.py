# -*- coding: utf-8 -*-
# Rec09 Radiko Recording Tools
# Copyright (C) 2020- yussi

import requests
import base64
import re
import time
import subprocess
from bs4 import BeautifulSoup
import datetime

class Radiko:
    def get_program_by_channel(self, channel, rec_time):
        # 週間番組表を取得する
        url = 'http://radiko.jp/v3/program/station/weekly/%s.xml' % channel
        r = requests.get(url)

        soup = BeautifulSoup(r.content, "xml")
        stations = soup.find_all("station")
        for l in stations:
            m = l.find("name").string
            progs = soup.find_all("prog")
            prog = {}
            for k in progs:
                p_ft = datetime.datetime.strptime(k['ft'], '%Y%m%d%H%M%S')
                p_to = datetime.datetime.strptime(k['to'], '%Y%m%d%H%M%S')

                # 現在放送中の番組を検索する
                if rec_time < p_ft:
                    continue
                if rec_time >= p_to:
                    continue

                # 現在放送中の番組を辞書型で返す
                prog['title'] = k.title.string
                prog['channel'] = m
                prog['id'] = k['id']
                prog['ft'] = p_ft
                prog['to'] = p_to
                prog['dur'] = k['dur']
                prog['ts_in_ng'] = k.ts_in_ng.string
                prog['url'] = k.url.string
                prog['desc'] = k.desc.string
                p_info = k.info.string
                if p_info != None:
                    p_info = BeautifulSoup(p_info, "html.parser").get_text()
                prog['info'] = p_info
                prog['pfm'] = k.pfm.string
                prog['img'] = k.img.string
                prog['hashtag'] = k.find("meta")['value']
                break

        return prog

    def get_channel_list(self, areaid):
        url = 'http://radiko.jp/v2/api/program/today?area_id=%s' % areaid
        r = requests.get(url)
        soup = BeautifulSoup(r.content, "xml")
        stations = soup.find_all("station")
        channel_list = []
        for l in stations:
            m = l['id']
            channel_list.append(m)
        return channel_list

    def auth(self):
        # auth urlやheaders, auth_keyの定義
        auth1_url = "https://radiko.jp/v2/api/auth1"
        auth2_url = "https://radiko.jp/v2/api/auth2"
        auth_key = "bcd151073c03b352e1ef2fd66c32209da9ca0afa"
        headers = {
          "X-Radiko-App": "pc_html5",
          "X-Radiko-App-Version": "0.0.1",
          "X-Radiko-User": "test-stream",
          "X-Radiko-Device": "pc"
        }
        # auth1にアクセス
        res = requests.get(auth1_url, headers=headers)
        if (res.status_code != 200):
            print("Auth1に失敗しました")
            return None

        AuthToken = res.headers["X-RADIKO-AUTHTOKEN"]
        KeyLength = int(res.headers["X-Radiko-KeyLength"])
        KeyOffset = int(res.headers["X-Radiko-KeyOffset"])
        tmp_authkey = auth_key[KeyOffset:KeyOffset+KeyLength]
        AuthKey = base64.b64encode(tmp_authkey.encode('utf-8')).decode('utf-8')
        
        headers = {
            "X-Radiko-AuthToken": AuthToken,
            "X-Radiko-PartialKey": AuthKey,
            "X-Radiko-User": "test-stream",
            "X-Radiko-Device": "pc"
        }
        # auth2にアクセス
        res = requests.get(auth2_url, headers=headers)
        if (res.status_code != 200):
            print("Auth2に失敗しました")
            return None
        
        area = res.text.strip().split(",")
        areaid = area[0]
        return AuthToken, areaid

    def record_streaming(self, channel, duration, output):
        # 一旦radikoプレミアムなしで認証
        AuthToken, areaid = self.auth() 

        # 録音する局がプレミアムなしで録音できる局かどうかを判定する
        if channel not in self.get_channel_list(areaid):
            print("地域判定は、%sです。現在の地域判定では録音できません。" % areaid)
            # 本来ならばここで、プレミアムの認証に移る
            return None
        
        print("地域判定は、%sです。現在の地域判定で録音できます。" % areaid)

        headers = {"X-Radiko-AuthToken": AuthToken}
        # m3u8プレイリストを取得する
        url = 'http://f-radiko.smartstream.ne.jp/%s/_definst_/simul-stream.stream/playlist.m3u8' % channel
        res = requests.get(url, headers=headers)
        res.encoding = "utf-8"
        if (res.status_code != 200):
            print(res.text)

        body = res.text
        lines = re.findall( '^https?://.+m3u8$' , body, flags=(re.MULTILINE) )
        if len(lines) <= 0:
            print("m3u8プレイリストを取得できませんでした")
            return None
        print(lines[0])
        m3u8 = lines[0]

        # 録音する番組のデータを取得する
        prog_data = self.get_program_by_channel(channel, datetime.datetime.now())
        print('録画する放送局は%s、番組名は%sです' % (prog_data['channel'], prog_data['title']))

        # ファイル名を決める
        output = output + "_" + datetime.datetime.now().strftime('%Y-%m-%d') + ".m4a"
        print('録音ファイル名は、%sです' % output)

        # 番組名が取得できていない場合の録音スクリプト
#        command = ('ffmpeg -loglevel error -headers "X-Radiko-AuthToken: %s" -i "%s" -acodec copy  "%s"' % (AuthToken, m3u8, output))


        title = prog_data['ft'].strftime('%Y-%m-%d') + "放送_" + prog_data['title'] 
        # ffmpegで録音する
        command = ('ffmpeg -loglevel error -headers "X-Radiko-AuthToken: %s" -i "%s" -metadata title="%s" -metadata artist="%s" -metadata album="%s" -acodec copy  "%s"' % (AuthToken, m3u8, title, prog_data['pfm'], prog_data['title'], output))
        print(command)

        p1 = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, shell=True)
        time.sleep(int(duration)*60)
        p1.communicate(b'q')

        return None
    
    def record_timefree(self, channel, start, end, output):
        return None

if __name__ == '__main__':
    radiko = Radiko()
    radiko.record_streaming("CBC", "1", "test2")