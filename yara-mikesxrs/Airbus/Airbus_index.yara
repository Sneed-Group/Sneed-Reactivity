rule derusbi_kernel
{
    meta:
        description = "Derusbi Driver version"
        date = "2015-12-09"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
        reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
    strings:
	$token1 = "$$$--Hello"     
	$token2 = "Wrod--$$$"   
	$cfg = "XXXXXXXXXXXXXXX"
	$class = ".?AVPCC_BASEMOD@@"
	$MZ = "MZ"

    condition:
        $MZ at 0 and $token1 and $token2 and $cfg and $class
}

rule derusbi_linux
{
    meta:
        description = "Derusbi Server Linux version"
        date = "2015-12-09"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
        Reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
    strings:
	$PS1 = "PS1=RK# \\u@\\h:\\w \\$"
	$cmd = "unset LS_OPTIONS;uname -a"
	$pname = "[diskio]"
	$rkfile = "/tmp/.secure"
	$ELF = "\x7fELF"

    condition:
        $ELF at 0 and $PS1 and $cmd and $pname and $rkfile
}

rule sakula_v1_0
{
    meta:
        description = "Sakula v1.0"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/09/APT-BlackVine-Malware-Sakula"
    strings:
        $m1 = "%d_of_%d_for_%s_on_%s"
        $m2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m3 = "=%s&type=%d"
        $m4 = "?photoid="
        $m5 = "iexplorer"
                $m6 = "net start \"%s\""
        $v1_1 = "MicroPlayerUpdate.exe"
        $MZ = "MZ"
    condition:
        $MZ at 0 and all of ($m*) and not $v1_1
}

rule sakula_v1_1
{
    meta:
        description = "Sakula v1.1"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/09/APT-BlackVine-Malware-Sakula"
    strings:
        $m1 = "%d_of_%d_for_%s_on_%s"
        $m2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m3 = "=%s&type=%d"
        $m4 = "?photoid="
        $m5 = "iexplorer"
                $m6 = "net start \"%s\""
        $v1_1 = "MicroPlayerUpdate.exe"
        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}

rule sakula_v1_2
{
    meta:
        description = "Sakula v1.2"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/09/APT-BlackVine-Malware-Sakula"
    strings:
        $m1 = "%d_of_%d_for_%s_on_%s"
        $m2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m3 = "cmd.exe /c rundll32 \"%s\""
        $v1_1 = "MicroPlayerUpdate.exe"
        $v1_2 = "CCPUpdate"

        $MZ = "MZ"
    condition:
        $MZ at 0 and $m1 and $m2 and $m3 and $v1_2 and not $v1_1
}

rule sakula_v1_3
{
    meta:
        description = "Sakula v1.3"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/09/APT-BlackVine-Malware-Sakula"
    strings:
        $m1 = "%d_of_%d_for_%s_on_%s"
        $m2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m3 = "cmd.exe /c rundll32 \"%s\""

        $v1_3 = { 81 3E 78 03 00 00 75 57  8D 54 24 14 52 68 0C 05 41 00 68 01 00 00 80 FF  15 00 F0 40 00 85 C0 74 10 8B 44 24 14 68 2C 31  41 00 50 FF 15 10 F0 40 00 8B 4C 24 14 51 FF 15  24 F0 40 00 E8 0F 09 00 }

        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}

rule sakula_v1_4
{
    meta:
        description = "Sakula v1.4"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/09/APT-BlackVine-Malware-Sakula"
    strings:
        $m1 = "%d_of_%d_for_%s_on_%s"
        $m2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m3 = "cmd.exe /c rundll32 \"%s\""

        $v1_4 = { 50 E8 CD FC FF FF 83 C4  04 68 E8 03 00 00 FF D7 56 E8 54 12 00 00 E9 AE  FE FF FF E8 13 F5 FF FF }

        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}

rule sakula_v2_0
{
    meta:
        description = "Sakula v2.0 - The bytes string matchs a specific decryption routine (xor 0x33) (VirtualAlloc + memcpy + loop)"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"

    strings:
        $m = { 8B 75 DC 2B F3 6A 40 68  00 10 00 00 56 6A 00 FF 15 04 20 40 00 8B F8 85  FF 74 4A 56 8B 4D E0 03 CB 51 57 E8 3C 02 00 00  83 C4 0C C7 45 FC 00 00 00 00 B3 33 33 D2 89 55  D8 88 5D E7 3B D6 73 11 0F B6 CB 0F B6 04 3A 33  C8 88 0C 3A FE C3 42 EB E5 FF D7 EB }

        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}

rule sakula_v2_1
{
    meta:
        description = "Sakula v2.1"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m1 = "Sakula"
        $m2 = "%d_of_%d_for_%s_on_%s"
        $m3 = "Create Child Cmd.exe Process Succeed!"
        $v2_1 = "\\drivers\\etc\\hosts"

        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}

rule sakula_v2_2
{
    meta:
        description = "Sakula v2.2"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m1 = "Sakula"
        $m2 = "%d_of_%d_for_%s_on_%s"
        $m3 = "Create Child Cmd.exe Process Succeed!"
        $v2_1 = "\\drivers\\etc\\hosts"

        $MZ = "MZ"
    condition:
        $MZ at 0 and all of ($m*) and not $v2_1
}

rule sakula_v3_0
{
    meta:
        description = "Sakula v3.0"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m1 = "Mozilla/4.0+(compatible;+MSIE+8.0;+Windows+NT+5.1;+SV1)"
        $m2 = "ry.db"
        $m3 = "cmd.exe /c reg add %s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v \"%s\" /t REG_SZ /d \"%s\""
        $m4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}

rule sakula_v3_1
{
    meta:
        description = "Sakula v3.1"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)"
        $m2 = ".NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)"
        $m3 = "Self Process Id:"
        $m4 = "msi.dll"
        $m5 = "setup.msi"
        $m6 = "%WINDIR%\\system32\\svchost.exe"

        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}

rule sakula_v3_2  {
    meta:
        description = "Sakula v3.2"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m1 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m2 = "%TEMP%\\"
        $m3 = "Emabout.dll"
        $m4 = "Thumbs.db"
        $m5 = "shutil.dll"
        $m6 = "CloseAbout"
                $m7 = "rundll32.exe"

    condition:
        all of them
}

rule sakula_packed_v2_0
{
    meta:
        description = "Sakula packer v2.0 - The bytes string matchs 2 concatenated functions. The first function returns the offset of the second function, and the second function returns the payload offset (hardcoded)"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m = { 55 8B EC 51 53 56 57 E8  00 00 00 00 58 05 13 00 00 00 89 45 FC 8B 45 FC  5F 5E 5B 8B E5 5D C3 4D }

        $MZ = "MZ"
    condition:
        all of them
}

rule sakula_packed_v2_1
{
    meta:
        description = "Sakula packer v2.1 - The bytes string matchs a specific decryption routine. It starts by xoring the payload many times (an even number) with 0x32. It is cryptographically useless, but it simulates a Sleep. Then, it decrypts the payload with a xor 0x33"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m = { 33 C0 B2 32 85 F6 74 0D  30 14 38 8D 0C 38 40 FE C2 3B C6 72 F3 81 FB FF  FF 01 00 74 0B 43 81 FB 00 00 00 01 7C DA EB 15  33 C9 B2 33 85 F6 74 0D 30 14 39 8D 04 39 41 FE  C2 3B CE 72 F3 83 EC 0C}

    condition:
        all of them
}

rule sakula_packed_v2_2
{
    meta:
        description = "Sakula packer v2.2"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m = "goldsunfucker"

    condition:
        all of them
}

rule sakula_packed_v3_1
{
    meta:
        description = "Sakula v3.1 packed shellcode"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m1 = "AAAA"
        $m2 = "BBBB"
        $m3 = "CCCC"

        $MZ = "MZ"
    condition:
        all of ($m*) and @m1 < @m2 and @m2 < @m3 and $MZ at @m3+4
}

rule sakula_dropper_v3_1
{
    meta:
        description = "Sakula v3.1 dropper"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m1 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m2 = "%TEMP%\\"
        $m3 = "s.exe"
        $m4 = "setup.msi"
        $m5 = "msi.dll"
    condition:
        all of them
}

rule vx_protector  {
    meta:
        description = "vx protector (used as a protection layer by Sakula) - The bytes string match a specific layer of protection inserted manually before the real code. It decrypts the real code and jumps on it."
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m1 = { 89 FF 55 89 E5 83 EC 20 A1 08 30 40 00 83 F8 00 75 0F A1 0C 30 40 00 83 F8 00 75 05 E9 95 00 00 00 E8 FA 60 00 00 89 45 FC 68 88 13 00 00 E8 F3 60 00 00 E8 C8 5F 00 00 83 F8 00 74 E4 89 45 EC E8 DB 60 00 00 2B 45 FC 3D 88 13 00 00 7C D2 8D 45 F8 50 E8 AE 5F 00 00 83 F8 00 74 C4 A1 08 30 40 00 83 F8 00 74 2C 68 E8 03 00 00 E8 B5 60 00 00 8D 45 F0 50 E8 8C 5F 00 00 83 F8 00 74 E8 8B 45 FC 8B 5D F4 39 D8 74 98 8B 45 F8 8B 5D F0 39 D8 74 D4 A1 0C 30 40 00 83 F8 00 74 19 68 88 13 00 00 E8 7F 60 00 00 E8 54 5F 00 00 83 F8 00 74 E2 3B 45 EC 90 90 FF 35 00 30 40 00 B8 1A 30 40 00 BB 71 32 40 00 29 C3 53 68 1A 30 40 00 E8 25 1B 00 00 8D 45 FC 50 6A 40 B8 2A 11 40 00 BB F8 2B 40 00 29 C3 53 68 2A 11 40 00 E8 3C 60 00 00 FF 35 04 30 40 00 B8 2A 11 40 00 BB F8 2B 40 00 29 C3 53 68 2A 11 40 00 E8 EB 1A 00 00 8D 45 FC 50 FF 30 B8 2A 11 40 00 BB F8 2B 40 00 29 C3 53 68 2A 11 40 00 E8 02 60 00 00 EC EC EC EC EC EC}

    condition:
        all of them
}