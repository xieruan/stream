# Stream Unlock
流媒体解锁后端

## 推荐系统
- Debian 10
- Ubuntu 20.04
- CentOS 8 Stream

## 安装Unzip解压程序
```bash
yum install -y unzip zip
```

## 安装Yum安装
```bash
yum -y install wget
```

## 一键部署
```bash
curl -fsSL https://raw.githubusercontent.com/xieruan/stream/master/scripts/kickstart.sh | bash
```

升级

```bash
curl -fsSL https://raw.githubusercontent.com/xieruan/stream/master/scripts/upgrade.sh | bash
```
卸载
```bash
curl -fsSL https://raw.githubusercontent.com/xieruan/stream/master/scripts/remove.sh | bash
```

## 配置文件
Stream
```
/etc/stream.json
# 访问端口 "addr": ":8888",
# 访问秘钥 "secret": "weiguanyun"

请自行增加解锁内容
twitter.com 全国
pscp.tv 全国
periscope.tv 全国
t.co 全国
twimg.co 全国
twimg.com 全国
twitpic.com 全国
twitter.jp 全国
vine.co 全国
syosetu.com 日本
rakuten.co.jp 日本
disney-plus.net 美国 新加坡
disneyplus.com 美国 新加坡
registerdisney.go.com 美国 新加坡
disneynow.com 美国 新加坡
dssott.com 美国 新加坡
bamgrid.com 美国 新加坡
go-mpulse.net 美国 新加坡
gstatic.com 美国 新加坡
googlevideo.com 全国
youtube.com 全国
ytimg.com 全国
googleapis.com 全国
yt3.ggpht.com 全国



```

## DDNSAPI
```
curl -fsSL http://DNSIP:8888/aio?secret=weiguanyun
注意替换 IP 和端口，写入 crontab 即可
```

## 控制命令
```
# 启动服务并开启自启
systemctl enable --now stream

# 停止服务并关闭自启
systemctl disable --now stream

# 查看启动服务状态
systemctl status stream

# 查看DNS服务状态
systemctl status smartdns

# 获取实时日志
journalctl -f -u stream
```
