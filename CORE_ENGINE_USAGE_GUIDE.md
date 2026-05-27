# CrimsonWeb Core Engine v2.1 Kullanim Kilavuzu

Bu kilavuz guncel `core_engine.py` ve `crimsonweb` CLI girisi icindir. Kod her guncellendiginde bu dosya da guncellenmelidir.

Son guncelleme: 2026-05-24

## 1. Kisa Ozet

CrimsonWeb Core Engine yetkili guvenlik testi icin gelistirilmis bir servis ve web tarama aracidir.

Arac su isleri yapabilir:

- TCP port kesfi
- Opsiyonel SYN scan
- Servis ve banner tespiti
- HTTP/HTTPS tespiti
- WAF/header tespiti
- Hassas path ve API endpoint kontrolu
- HTTP security header analizi
- Cookie flag kontrolu
- CORS misconfiguration kontrolu
- TLS sertifika metadata ozeti
- CVE eslestirme
- Tor/proxy/multi-egress web istekleri
- Ban/block sinyali algilama
- State/resume
- JSON, CSV, Markdown ve executive rapor uretimi

Zorunlu guvenlik kontrolu:

```bash
--roe <izin-referansi>
```

Bu parametre olmadan arac calismaz. RoE, yani Rules of Engagement / yazili izin referansidir.
Uc format da ayni isi yapar: `--roe-confirmed`, `--roe`, `--r`.

## 2. En Onemli Mantik

`--top-ports` artik 1000 portluk gomulu listeyi kullanir.

Nmap kullanilmaz:

- Nmap komutu calistirilmaz.
- `/usr/share/nmap/nmap-services` okunmaz.
- Dis dosyadan port listesi cekilmez.

Egress kurallari:

- `--web-tor`, `--web-proxy`, `--web-proxy-file` ve `--egress-config` sadece `--web-only` ile kullanilir.
- SOCKS proxy icin `socks5h://` veya `socks4a://` kullan; `socks5://` lokal DNS riski nedeniyle reddedilir.
- `egress.yml` icinde `mode: direct` kullanma; direct mod icin `--egress-config` verme.
- Normal TCP port discovery proxy pool'dan gecmez; VPS uzerinde calisiyorsa VPS IP'sinden cikar.

En hizli ilk gecis:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr --top-ports --fast --port-scan-only --output-dir reports
```

Paket kurulumundan sonra ayni komut kisa CLI ile de calisir:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr --top-ports --fast --port-scan-only --output-dir reports
```

Tool-style kullanim:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF -t hedef-domain.gov.tr --top-ports --no-cve
sudo venv/bin/crimsonweb --roe RoE-REF -u https://hedef-domain.gov.tr --no-cve
```

`-u/--url` verirsen crimsonweb URL'den host'u alir, port belirtilmediyse `http=80` veya `https=443` secer ve web-only modda calisir.

Detayli servis analizi icin sadece acik portlari tekrar tara:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr -p 80,443,8080 --fast --output-dir reports
```

## 3. Kali Linux Kurulum

Proje klasorune gir:

```bash
cd ~/SparkleProject
```

En pratik Kali kurulumu:

```bash
chmod +x scripts/install_kali.sh
./scripts/install_kali.sh
sudo ln -sf "$(pwd)/venv/bin/crimsonweb" /usr/local/bin/crimsonweb
crimsonweb --version
```

Not: `install_kali.sh` Python paketlerini `pip` ile kurar. Internet olmayan ortamda once paketleri offline wheel olarak hazirlaman gerekir.

Python venv olustur:

```bash
python3 -m venv venv
```

Venv aktif et:

```bash
source venv/bin/activate
```

Paketleri kur:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip uninstall -y crimson-core-engine
python -m pip install -e .
```

Test:

```bash
crimsonweb -h
crimsonweb --version
```

Sen bu projede Kali'de araci genelde root yetkisiyle calistiriyorsun. Bu desteklenir:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr --top-ports --no-cve
```

sqlmap benzeri kisa kullanim:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF -t hedef-domain.gov.tr --top-ports --no-cve
sudo venv/bin/crimsonweb --roe RoE-REF -u https://hedef-domain.gov.tr --no-cve
```

Normal async-connect tarama icin teknik olarak `sudo` gerekmez, ama root ile calistirirsan kod calismaya devam eder. Audit log'da `operator=root`, varsa `sudo_user=<kali-kullanicisi>` ve `elevated=true` bilgisi yazilir.

Eski kullanim da hala desteklenir:

```bash
sudo venv/bin/python core_engine.py --roe RoE-REF hedef-domain.gov.tr --top-ports --no-cve
```

Bu komut hizli ilk pass icin ideal degildir:

```bash
sudo venv/bin/crimsonweb --r LAB-SCANME-TEST scanme.nmap.org --top-ports --no-cve
```

Nedeni: `--no-cve` sadece CVE sorgusunu kapatir; servis fingerprint ve web kontrolleri yine calisir. Hizli ilk pass icin bunu kullan:

```bash
sudo venv/bin/crimsonweb --r LAB-SCANME-TEST scanme.nmap.org --top-ports --fast --port-scan-only --output-dir reports
```

Sadece `--syn` kullanirsan root gerekir:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr --top-ports --syn
```

## 4. Windows Kurulum

Proje klasorune gir:

```powershell
cd C:\Users\mstfc\Documents\Codex\2026-04-28\files-mentioned-by-the-user-core
```

Venv olustur:

```powershell
py -3 -m venv venv
```

Venv aktif et:

```powershell
.\venv\Scripts\Activate.ps1
```

PowerShell script calistirmayi engellerse sadece o terminal icin izin ver:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

Paketleri kur:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip uninstall -y crimson-core-engine
python -m pip install -e .
```

Test:

```powershell
crimsonweb -h
```

Windows'ta normal async-connect scan icin Administrator gerekmez. `--syn` icin Administrator ve Scapy/Npcap gerekir.

## 5. Temel Komutlar

Yardim ekrani:

```bash
crimsonweb -h
```

Versiyon:

```bash
crimsonweb --version
```

Tek port:

```bash
crimsonweb --roe RoE-REF hedef-domain.gov.tr -p 443 --no-cve
```

Tek hedef, tool-style:

```bash
crimsonweb --roe RoE-REF -t hedef-domain.gov.tr -p 443 --no-cve
```

URL'den web kontrolu:

```bash
crimsonweb --roe RoE-REF -u https://hedef-domain.gov.tr --no-cve
```

Birden fazla port:

```bash
crimsonweb --roe RoE-REF hedef-domain.gov.tr -p 80,443,8080 --no-cve
```

Port araligi:

```bash
crimsonweb --roe RoE-REF hedef-domain.gov.tr -p 8000-8100 --no-cve
```

Top 1000 TCP port:

```bash
crimsonweb --roe RoE-REF hedef-domain.gov.tr --top-ports --no-cve
```

Top 100 port:

```bash
crimsonweb --roe RoE-REF hedef-domain.gov.tr --top-ports --top-ports-count 100 --no-cve
```

Passive recon decoy link limitini degistir:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr -p 80,443 --decoy-rate 0.1 --recon-max-links 10 --no-cve
```

TLS sertifika dogrulamayi kapatma sadece RoE kapsaminda ve self-signed/internal sertifika gerekiyorsa kullanilmalidir:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr -p 443 --tls-no-verify --no-cve
```

`--tls-no-verify` hem `aiohttp` hem `curl_cffi` istek motorunda ayni sekilde uygulanir ve audit log'a yazilir.

## 5.1 Advanced Web ve UDP Kontrolleri

v2.1 ile eklenen guvenli advanced kontroller:

- UDP kapsaminda varsayilan olarak 53, 69, 123, 161, 500, 1900, 5353 portlari icin ayri probe payload'lari.
- UDP/500 IKE kontrolu IKEv2 SA_INIT formatinda probe kullanir.
- UDP/514 syslog varsayilan kapsama dahil degildir; SIEM/log girdisi uretme riski nedeniyle sadece `--udp-include-syslog` ile opt-in calisir.
- HTTP security header analizi: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- Cookie flag analizi: HttpOnly, Secure, SameSite.
- CORS kontrolu: untrusted `Origin: https://crimsonweb.invalid` ile tek kontrollu istek.
- API endpoint indikatorleri: `/api`, `/api/v1`, `/graphql`, `/swagger-ui.html`, `/openapi.json` gibi modern path'ler.
- TLS sertifika ozeti: subject CN, issuer CN, expiry, SAN, cipher, ALPN/HTTP2 bilgisi.
- MITRE ATT&CK mapping: servis, CVE, hassas path, API ve web hardening bulgulari raporda tekniklerle iliskilendirilir.
- CVE lookup cache'i 500 kayitlik LRU limitlidir; uzun taramalarda bellek kontrolsuz buyumez.

UDP kontrolunu acmak:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr -p 80,443 --udp --no-cve --output-dir reports
```

Syslog dahil UDP kontrolu, sadece RoE kapsaminda acikca izin varsa:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr -p 80,443 --udp --udp-include-syslog --no-cve --output-dir reports
```

Web advanced kontrolleri normal servis tespitinin parcasidir. Istersen tamamini kapatmak icin:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr -p 80,443 --no-web-checks --no-cve
```

Not: FIN/XMAS/NULL gibi TCP flag scan modlari eklenmedi. Bunlar siklikla IDS/IPS bypass amaciyla kullanildigi icin crimsonweb'in RoE odakli assessment profilinde yok. SYN modu var ama sadece root/Administrator ile ve rate limit profilin korunarak calisir.

## 6. Hizli ve Verimli Kullanim

Ilk pass icin onerilen komut:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr --top-ports --fast --port-scan-only --output-dir reports
```

Bu mod:

- 1000 portu tarar
- Timeout'u dusurur
- Concurrency'yi artirir
- Web global rate cap'i hizli mod icin yukseltir
- CVE sorgusunu kapatir
- Passive recon'u kapatir
- Web path kontrollerini kapatir
- Sadece acik portlari raporlar

Not: `--top-ports` artik 1000 port taradigi icin eski 298 portluk halden dogal olarak daha uzun surer. Ilk pass icin mutlaka `--fast --port-scan-only` kullan.

Acik portlar ciktiktan sonra detayli servis analizi:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr -p 80,443,8080 --fast --output-dir reports
```

CVE de istiyorsan `--fast` kullanma veya `--no-cve` verme:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr -p 80,443,8080 --output-dir reports
```

## 7. Belediye Senaryosu Icin Onerilen Akis

Once izin referansini belirle:

```text
RoE-2026-BLD-001
```

1. Hizli port kesfi:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr --top-ports --fast --port-scan-only --output-dir reports
```

2. Acik portlari detaylandir:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr -p 80,443,8080 --fast --output-dir reports
```

3. RoE izin veriyorsa CVE eslestirme:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr -p 80,443,8080 --output-dir reports
```

4. Web-only Tor/proxy testi gerekiyorsa sadece web portlarinda kullan:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr --web-only --web-tor -p 80,443 --no-cve --output-dir reports
```

## 8. Tor Kullanimi - Kali Linux

Tor servisini kur:

```bash
sudo apt update
sudo apt install tor
```

Servisi baslat:

```bash
sudo systemctl start tor
sudo systemctl status tor
```

Varsayilan Tor SOCKS adresi:

```text
socks5h://127.0.0.1:9050
```

Kodda `--web-tor` bu adresi kullanir.

Tor ile sadece web-only mod desteklenir:

```bash
crimsonweb --roe RoE-REF hedef-domain.gov.tr --web-only --web-tor -p 80,443 --no-cve --output-dir reports
```

Neden `--web-only` zorunlu:

- TCP port discovery Tor SOCKS uzerinden gecmez.
- Web istekleri Tor/proxy uzerinden gecer.
- Bu yuzden Tor modu sadece web istekleri icin guvenli sekilde kullanilir.

Yeni Tor circuit istemek icin:

```bash
crimsonweb --roe RoE-REF hedef-domain.gov.tr --web-only --web-tor -p 80,443 --tor-new-identity --no-cve
```

Not: `--tor-new-identity` icin Tor control port erisimi gerekir. Varsayilan control port `9051`.

## 9. Tor Browser ile Kullanim

Tor Browser genelde SOCKS portu olarak `9150` kullanir.

Bu durumda `--web-tor` yerine legacy proxy parametresi kullan:

```bash
crimsonweb --roe RoE-REF hedef-domain.gov.tr --web-only --web-proxy socks5h://127.0.0.1:9150 -p 80,443 --no-cve
```

Tor Browser ile `--tor-new-identity` her zaman calismayabilir; control port acik degilse kullanma.

Sunumda basit anlatim:

```text
Port taramasi dogrudan TCP seviyesinde calisir. Tor ise SOCKS uzerinden web isteklerini tasir. Bu nedenle Tor entegrasyonunu web-only modda kullaniyoruz. Domain DNS cozumlemesi de bu modda lokalden yapilmaz; istek socks5h uzerinden gider.
```

## 10. VPS ile Kullanim

VPS kullanimi icin iki farkli model var.

En dogru model:

```text
Scanner VPS uzerinde calisir -> hedef belediye sitesi VPS public IP'sini gorur.
```

Sinirli model:

```text
Scanner lokal makinede calisir -> sadece web-only istekler SSH SOCKS tuneli ile VPS'ten cikar.
```

Tam port taramasini VPS IP'sinden yapmak istiyorsan araci VPS uzerinde calistirmalisin. `--web-proxy` veya SOCKS tuneli sadece HTTP/HTTPS web-only istekleri icindir; normal TCP port discovery'yi proxy uzerinden tasimaz.

### 10.1 VPS Secimi

Belediye veya kurum IP listesi istiyorsa VPS icin sunlari sec:

- Statik IPv4 adresi olan VPS
- Tarama boyunca degismeyen IP
- Tercihen tek amacli, temiz kurulum
- Ubuntu Server, Debian veya Kali tabanli sistem
- SSH erisimi

VPS IP'sini kontrol et:

```bash
curl -4 ifconfig.me
```

Bu IP'yi RoE kapsaminda belediye BT/SOC ekibine bildir:

```text
Scanner egress IP: <VPS_PUBLIC_IPV4>
Hostname: <vps-hostname>
Operator: <ad-soyad>
RoE reference: RoE-2026-BLD-001
Scan window: <tarih/saat araligi>
Rate limit: <ornek 20 req/dk web-only veya port scan profili>
```

### 10.2 VPS Hazirlik

VPS'e SSH ile baglan:

```bash
ssh kali@VPS_PUBLIC_IP
```

Sistem paketlerini guncelle:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git curl tmux
```

Proje dosyalarini VPS'e aktar. Lokal makineden:

```bash
scp -r ~/SparkleProject kali@VPS_PUBLIC_IP:~/SparkleProject
```

VPS uzerinde proje klasorune gir:

```bash
cd ~/SparkleProject
```

Venv olustur:

```bash
python3 -m venv venv
```

Bagimliliklari kur:

```bash
venv/bin/python -m pip install --upgrade pip
venv/bin/python -m pip install -r requirements.txt
```

Yardim ekranini test et:

```bash
venv/bin/crimsonweb -h
```

### 10.3 VPS Uzerinde Hizli Ilk Pass

Sen genelde root yetkisiyle calistirdigin icin VPS'te de ayni kalip:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr --top-ports --fast --port-scan-only --output-dir reports
```

Bu komut:

- VPS public IP'sinden cikis yapar
- 1000 gomulu top portu tarar
- Sadece acik portlari bulur
- Servis fingerprint, CVE ve web path kontrollerini atlar
- Ilk kesif icin en hizli profildir

### 10.4 VPS Uzerinde Detayli Servis Analizi

Ilk pass sonucunda acik portlar ornegin `80,443,8080` geldiyse:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr -p 80,443,8080 --fast --no-cve --output-dir reports
```

CVE dahil daha detayli rapor istiyorsan:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr -p 80,443,8080 --output-dir reports
```

### 10.5 Uzun Tarama Icin tmux

SSH koparsa tarama yarida kalmasin diye `tmux` kullan:

```bash
tmux new -s crimsonweb
```

Taramayi baslat:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr --top-ports --fast --port-scan-only --output-dir reports
```

tmux'tan cikmadan ayril:

```text
Ctrl+B sonra D
```

Geri baglan:

```bash
tmux attach -t crimsonweb
```

### 10.6 Raporlari VPS'ten Alma

Lokal makineden:

```bash
scp -r kali@VPS_PUBLIC_IP:~/SparkleProject/reports ./reports-vps
```

VPS uzerinde raporlari listele:

```bash
ls -lah reports
```

### 10.7 VPS'i SSH SOCKS Proxy Olarak Kullanma

Bu model sadece web-only icindir. Tam port discovery icin kullanma.

Lokal makinede SSH SOCKS tuneli ac:

```bash
ssh -D 1080 -N kali@VPS_PUBLIC_IP
```

Baska terminalde lokal makineden web-only tara:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr --web-only --web-proxy socks5h://127.0.0.1:1080 -p 80,443 --no-cve --output-dir reports
```

Bu komutta:

- HTTP/HTTPS istekleri SSH SOCKS tunelinden VPS'e gider
- DNS cozumlemesi `socks5h` nedeniyle lokalden yapilmaz
- Normal TCP port taramasi yapilmaz

### 10.8 VPS + Proxy Pool Kullanimi

VPS + proxy pool kullanabilirsin, ama hangi trafik hangi IP'den cikiyor bunu net ayirmalisin.

Kodun davranisi:

```text
Normal TCP port discovery -> scanner'in calistigi makinenin IP'sinden cikar.
Web-only HTTP/HTTPS istekleri -> --egress-config proxy pool uzerinden cikabilir.
```

Yani scanner VPS uzerinde calisiyorsa:

- `--top-ports`, `--fast`, `--port-scan-only` gibi port discovery trafiÄŸi VPS public IP'sinden cikar.
- `--web-only --egress-config egress.yml` ile yapilan HTTP/HTTPS kontrolleri proxy pool IP'lerinden cikar.

Bu yuzden en temiz akis:

1. VPS IP'siyle hizli port kesfi yap.
2. Acik web portlarini proxy pool ile web-only tara.

#### 10.8.1 RoE'ye Bildirilecek IP Listesi

Belediye/SOC ekibine hem VPS IP'sini hem proxy pool IP'lerini bildir:

```text
Scanner host IP:
- <VPS_PUBLIC_IPV4>

Approved proxy pool:
- <PROXY_EXIT_IP_1>
- <PROXY_EXIT_IP_2>
- <PROXY_EXIT_IP_3>

Not:
- TCP port discovery VPS IP'sinden gelecektir.
- HTTP/HTTPS web-only kontrolleri proxy pool IP'lerinden gelecektir.
- IP havuzu tarama suresince degismeyecektir.
```

Rotating/dynamic public proxy kullanma. Bu senaryoda uygun olan sey dedicated, statik, onceden bildirilen proxy/VPN IP havuzudur.

#### 10.8.2 VPS Uzerinde Port Discovery

VPS'e gir:

```bash
ssh kali@VPS_PUBLIC_IP
cd ~/SparkleProject
```

Ilk port kesfi:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr --top-ports --fast --port-scan-only --output-dir reports
```

Bu asamada hedef taraf VPS IP'sini gorur.

#### 10.8.3 Proxy Pool YAML Dosyasi

VPS uzerinde `egress.yml` olustur:

```yaml
mode: multi_egress
tor:
  enabled: false
proxies:
  - id: proxy-a
    url: http://user:pass@proxy-a.example:8080
    role: general
  - id: proxy-b
    url: http://user:pass@proxy-b.example:8080
    role: general
  - id: proxy-c
    url: socks5h://user:pass@proxy-c.example:1080
    role: general
```

Notlar:

- `socks5h` DNS cozumlemesini proxy tarafina tasir.
- `socks5://` ve `socks4://` kullanma; kod bunlari lokal DNS riski nedeniyle reddeder.
- `http://` proxy kullaniyorsan HTTPS CONNECT desteklediginden emin ol.
- `mode: direct` kullanma; direct mod icin `--egress-config` verilmez.
- Proxy credential'larini repo'ya commit etme.

#### 10.8.4 Proxy Pool ile Web-Only Tarama

Ilk pass'te acik web portlari `80,443,8080` geldiyse:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr --web-only --egress-config egress.yml -p 80,443,8080 --no-cve --output-dir reports
```

RoE'deki hiz limitine uymak icin:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr --web-only --egress-config egress.yml -p 80,443,8080 --web-request-delay 3 --web-sensitive-delay 5 --web-max-global-rate 20 --web-stop-statuses 403,429,503 --no-cve --output-dir reports
```

Bu asamada hedef taraf proxy pool IP'lerini gorur.

#### 10.8.5 Tek Komutta VPS + Proxy Pool Neden Reddedilir?

Asagidaki gibi non-web-only komut artik kod tarafinda reddedilir:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr --top-ports --egress-config egress.yml --no-cve --output-dir reports
```

Beklenen hata:

```text
--egress-config requires --web-only
```

Nedeni:

- Port discovery VPS IP'sinden cikar.
- Web portlarindaki HTTP/HTTPS probe'lar proxy pool'dan cikabilir.
- Non-web servis banner probe'lari yine VPS IP'sinden cikar.

Bu karisik davranis SOC korelasyonunu zorlastirir. Bu yuzden kod artik proxy pool'u sadece `--web-only` modunda kabul eder.

#### 10.8.6 Tum Trafik Proxy/VPN IP'lerinden Ciksin Istersen

HTTP proxy pool ile normal TCP port scan'i tasiyamazsin. Tum port tarama trafiginin farkli statik IP'lerden cikmasi gerekiyorsa pratik secenekler:

- Her approved VPS uzerinde scanner'i ayri calistir.
- VPS'in OS seviyesinde dedicated VPN'e route edilmesini sagla.
- Kurumun onayladigi statik egress gateway kullan.

Bu durumda hedef taraf port discovery trafigini o makinenin/VPN gateway'in public IP'sinden gorur.

#### 10.8.7 Kali Linux VPS + Proxy Pool Adim Adim

Bu bolum senin kullanim sekline gore yazildi: Kali uzerinde root yetkisiyle calistirma.

1. VPS'e baglan:

```bash
ssh kali@VPS_PUBLIC_IP
```

2. VPS public IP'sini dogrula:

```bash
curl -4 ifconfig.me
```

Bu IP, port discovery asamasinda hedefin gorecegi IP'dir.

3. Proje klasorune gir:

```bash
cd ~/SparkleProject
```

4. Venv ve bagimliliklari hazirla:

```bash
python3 -m venv venv
venv/bin/python -m pip install --upgrade pip
venv/bin/python -m pip install -r requirements.txt
```

5. Proxy pool dosyasini olustur:

```bash
nano egress.yml
```

Ornek icerik:

```yaml
mode: multi_egress
tor:
  enabled: false
proxies:
  - id: proxy-a
    url: http://user:pass@proxy-a.example:8080
    role: general
  - id: proxy-b
    url: socks5h://user:pass@proxy-b.example:1080
    role: general
```

Kaydet: `Ctrl+O`, Enter, cikis: `Ctrl+X`.

6. Ilk port kesfini VPS IP'siyle yap:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr --top-ports --fast --port-scan-only --output-dir reports
```

7. Terminal veya JSON rapordan acik web portlarini not al. Ornek:

```text
80,443,8080
```

8. Acik web portlarini proxy pool ile tara:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr --web-only --egress-config egress.yml -p 80,443,8080 --web-request-delay 3 --web-sensitive-delay 5 --web-max-global-rate 20 --web-stop-statuses 403,429,503 --no-cve --output-dir reports
```

9. Raporlari kontrol et:

```bash
ls -lah reports
```

10. Raporlari lokal makineye al:

```bash
scp -r kali@VPS_PUBLIC_IP:~/SparkleProject/reports ./reports-vps
```

Bu akista:

- Port discovery IP'si: VPS public IP
- Web-only proxy IP'leri: `egress.yml` icindeki proxy exit IP'leri
- Audit log: root ile calistigin icin `operator=root`, `sudo_user=kali`, `elevated=true` alanlarini yazar

### 10.9 VPS Guvenlik Notlari

- VPS IP'sini RoE kapsaminda onceden bildir.
- Tarama boyunca VPS IP'sini degistirme.
- `reports/`, audit log ve state dosyalarini sakla.
- Proxy/API sifrelerini repo'ya commit etme.
- SSH icin mumkunse key kullan.
- VPS'te sadece gerekli servisleri acik birak.
- Is bittikten sonra raporlari al, gereksiz credential dosyalarini temizle.

## 11. Dedicated VPN / Proxy Pool

Belediye statik IP havuzu istediyse Tor yerine onayli dedicated VPN/proxy IP listesi kullanilmalidir.

Ornek egress YAML:

```yaml
mode: multi_egress
tor:
  enabled: false
proxies:
  - id: vpn-a
    url: http://user:pass@vpn-a.example:8080
    role: general
  - id: vpn-b
    url: http://user:pass@vpn-b.example:8080
    role: general
```

Calistirma:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr --web-only --egress-config egress.yml -p 80,443 --no-cve
```

Onemli:

- Kod `--egress-config` icin `--web-only` zorunlu tutar.
- `mode: direct` iceren egress dosyalari reddedilir.
- SOCKS proxy kullanacaksan `socks5h://` veya `socks4a://` kullan.
- Proxy IP listesi RoE kapsaminda onceden bildirilmelidir.
- Tarama sirasinda IP havuzu degismemelidir.
- Proxy credential bilgilerini repo'ya commit etme.

## 12. Rate Limit ve Block Davranisi

Varsayilan web pacing:

- Genel web delay: `3.0` saniye
- Hassas endpoint delay: `5.0` saniye
- Global limit: `20 req/dk`
- Stop status: `403,429,503`

Belediye RoE ornegine uygun web komutu:

```bash
crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr --web-only --web-tor -p 80,443 --web-request-delay 3 --web-sensitive-delay 5 --web-max-global-rate 20 --web-stop-statuses 403,429,503 --no-cve --output-dir reports
```

Block/CAPTCHA/WAF sinyali gorulurse kod ilgili host/path hedefini block listesine alir ve devam etmez. Tum tarama degil, tetikleyen hedef durdurulur.

Guncel ban detection davranisi:

- `403`, `429`, `503` gibi stop status kodlari hard block kabul edilir.
- Sayfa iceriginde `captcha`, `access denied`, `request blocked` gibi kelimeler gecerse 2xx cevaplarda hemen hard block yapilmaz; soft signal olarak sayilir.
- Ayni egress node uzerinde soft signal esigi asilinca cooldown uygulanir.

CVE eslestirme notu:

- CPE/CVE eslestirmesi artik servis turuyle uyumlu urunlerde yapilir.
- Ambiguous banner'lar CVE uretmez; bu false-positive rapor riskini azaltir.
- Daha konservatif rapor icin `--no-cve` kullan.

## 13. Raporlar

Rapor klasoru:

```bash
--output-dir reports
```

Format secimi:

```bash
--format json
--format csv
--format markdown
```

Her calismada ana rapor uretilir:

```text
crimsonweb_<target>_<timestamp>.json
```

Varsayilan konum komutu calistirdigin klasordur. `--output-dir reports` verirsen JSON/CSV/Markdown rapor, executive `.md` raporu ve audit log dosyalari `reports/` altina yazilir.

Ayrica executive rapor uretilir:

```text
crimsonweb_<target>_<timestamp>.executive.md
```

Audit log dosyalari:

```text
crimsonweb_audit.log
crimsonweb_audit.jsonl
```

`--tor-control-password` gibi hassas CLI degerleri audit log'a maskelenerek yazilir.

JSONL audit event'leri arka plan writer kuyruguyla yazilir; async tarama task'lari dosya I/O nedeniyle bloklanmaz. Program kapanirken `close_audit_log()` kuyrugu flush eder ve writer thread en fazla 3 saniye beklenir.

## 14. Resume / State

Varsayilan state klasoru:

```text
~/.crimsonweb/state
```

Yarida kalan taramaya devam:

```bash
crimsonweb --roe RoE-REF hedef-domain.gov.tr --top-ports --resume --output-dir reports
```

Ozel state dosyasi:

```bash
crimsonweb --roe RoE-REF hedef-domain.gov.tr --top-ports --state-file state.json --resume
```

## 15. Diff / Onceki Raporla Karsilastirma

Onceki JSON raporla karsilastir:

```bash
crimsonweb --roe RoE-REF hedef-domain.gov.tr --top-ports --compare reports/eski_rapor.json --output-dir reports
```

Bu yeni acilan/kapanan portlari ve versiyon farklarini gosterir.

## 16. Sik Karsilasilan Hatalar

Hata:

```text
the following arguments are required: --roe
```

Cozum:

```bash
crimsonweb --roe RoE-REF hedef-domain.gov.tr --top-ports
```

Hata:

```text
--web-tor requires --web-only
```

Cozum:

```bash
crimsonweb --roe RoE-REF hedef-domain.gov.tr --web-only --web-tor -p 80,443
```

Hata:

```text
aiohttp_socks required for --web-tor
```

Cozum:

```bash
python -m pip install aiohttp-socks
```

Hata:

```text
--egress-config requires --web-only
```

Cozum:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr --web-only --egress-config egress.yml -p 80,443 --no-cve
```

Hata:

```text
SOCKS proxy URL must use remote-DNS scheme socks5h/socks4a
```

Cozum: `socks5://` yerine `socks5h://`, `socks4://` yerine `socks4a://` kullan.

Hata:

```text
--egress-config cannot use mode: direct
```

Cozum: `egress.yml` icinde `mode: multi_egress` veya `mode: tor_only` kullan. Direct mod icin `--egress-config` verme.

Hata:

```text
--syn requires elevated privileges
```

Cozum Kali:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr --top-ports --syn
```

Cozum Windows:

PowerShell'i Administrator olarak ac ve Scapy/Npcap kurulumunu kontrol et.

## 17. Hangi Komutu Ne Zaman Kullanirim?

En hizli ilk kontrol:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr --top-ports --fast --port-scan-only
```

Daha detayli ama hala hizli:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr -p 80,443,8080 --fast
```

CVE dahil detayli rapor:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr -p 80,443,8080
```

VPS uzerinde tam port taramasi:

```bash
ssh kali@VPS_PUBLIC_IP
cd ~/SparkleProject
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr --top-ports --fast --port-scan-only --output-dir reports
```

VPS uzerinde proxy pool ile web-only:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr --web-only --egress-config egress.yml -p 80,443,8080 --web-request-delay 3 --web-sensitive-delay 5 --web-max-global-rate 20 --web-stop-statuses 403,429,503 --no-cve --output-dir reports
```

Lokal makineden VPS SSH SOCKS ile sadece web-only:

```bash
ssh -D 1080 -N kali@VPS_PUBLIC_IP
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr --web-only --web-proxy socks5h://127.0.0.1:1080 -p 80,443 --no-cve --output-dir reports
```

Tor ile web-only:

```bash
sudo venv/bin/crimsonweb --roe RoE-REF hedef-domain.gov.tr --web-only --web-tor -p 80,443
```

Belediye RoE hiz limitine uygun:

```bash
sudo venv/bin/crimsonweb --roe RoE-2026-BLD-001 belediye-domain.gov.tr --web-only --web-tor -p 80,443 --web-request-delay 3 --web-sensitive-delay 5 --web-max-global-rate 20 --web-stop-statuses 403,429,503 --no-cve --output-dir reports
```

## 18. Bakim Notu

Kodda asagidaki alanlardan biri degisirse bu kilavuz da guncellenmelidir:

- CLI flag'leri
- Default timeout/concurrency degerleri
- Tor/proxy davranisi
- `--top-ports` listesi
- Rapor formatlari
- Audit log davranisi
- Test/kurulum gereksinimleri

