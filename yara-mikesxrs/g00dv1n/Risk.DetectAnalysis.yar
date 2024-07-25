rule VMdetectMisc
{
	meta:
		Description = "Risk.VMDtc.sm"
		ThreatLevel = "3"

	strings:
		$vbox1 = "VBoxService" nocase ascii wide
		$vbox2 = "VBoxTray" nocase ascii wide
		$vbox3 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase ascii wide
		$vbox4 = "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions" nocase ascii wide

		$wine1 = "wine_get_unix_file_name" ascii wide

		$vmware1 = "vmmouse.sys" ascii wide
		$vmware2 = "VMware Virtual IDE Hard Drive" ascii wide

		$miscvm1 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" nocase ascii wide
		$miscvm2 = "SYSTEM\\\\ControlSet001\\\\Services\\\\Disk\\\\Enum" nocase ascii wide

		$vmdrv1 = "hgfs.sys" ascii wide
		$vmdrv2 = "vmhgfs.sys" ascii wide
		$vmdrv3 = "prleth.sys" ascii wide
		$vmdrv4 = "prlfs.sys" ascii wide
		$vmdrv5 = "prlmouse.sys" ascii wide
		$vmdrv6 = "prlvideo.sys" ascii wide
		$vmdrv7 = "prl_pv32.sys" ascii wide
		$vmdrv8 = "vpc-s3.sys" ascii wide
		$vmdrv9 = "vmsrvc.sys" ascii wide
		$vmdrv10 = "vmx86.sys" ascii wide
		$vmdrv11 = "vmnet.sys" ascii wide

		$vmsrvc1 = "vmicheartbeat" ascii wide
		$vmsrvc2 = "vmicvss" ascii wide
		$vmsrvc3 = "vmicshutdown" ascii wide
		$vmsrvc4 = "vmicexchange" ascii wide
		$vmsrvc5 = "vmci" ascii wide
		$vmsrvc6 = "vmdebug" ascii wide
		$vmsrvc7 = "vmmouse" ascii wide
		$vmsrvc8 = "VMTools" ascii wide
		$vmsrvc9 = "VMMEMCTL" ascii wide
		$vmsrvc10 = "vmware" ascii wide
		$vmsrvc11 = "vmx86" ascii wide
		$vmsrvc12 = "vpcbus" ascii wide
		$vmsrvc13 = "vpc-s3" ascii wide
		$vmsrvc14 = "vpcuhub" ascii wide
		$vmsrvc15 = "msvmmouf" ascii wide
		$vmsrvc16 = "VBoxMouse" ascii wide
		$vmsrvc17 = "VBoxGuest" ascii wide
		$vmsrvc18 = "VBoxSF" ascii wide
		$vmsrvc19 = "xenevtchn" ascii wide
		$vmsrvc20 = "xennet" ascii wide
		$vmsrvc21 = "xennet6" ascii wide
		$vmsrvc22 = "xensvc" ascii wide
		$vmsrvc23 = "xenvdb" ascii wide

		$miscproc1 = "vmware2" ascii wide
		$miscproc2 = "vmount2" ascii wide
		$miscproc3 = "vmusrvc" ascii wide
		$miscproc4 = "vmsrvc" ascii wide
		$miscproc5 = "vboxservice" ascii wide
		$miscproc6 = "vboxtray" ascii wide
		$miscproc7 = "xenservice" ascii wide

		$vmware_mac_1a = "00-05-69"
		$vmware_mac_1b = "00:05:69"
		$vmware_mac_2a = "00-50-56"
		$vmware_mac_2b = "00:50:56"
		$vmware_mac_3a = "00-0C-29"
		$vmware_mac_3b = "00:0C:29"
		$vmware_mac_4a = "00-1C-14"
		$vmware_mac_4b = "00:1C:14"
		$virtualbox_mac_1a = "08-00-27"
		$virtualbox_mac_1b = "08:00:27"

	condition:
		2 of them
}

rule SandboxDetectMisc
{
	meta:
		Description = "Risk.SBDtc.sm"
		ThreatLevel = "3"

	strings:
		$sbxie1 = "sbiedll" nocase ascii wide

		$prodid1 = "55274-640-2673064-23950" ascii wide
		$prodid2 = "76487-644-3177037-23510" ascii wide
		$prodid3 = "76487-337-8429955-22614" ascii wide

		$proc1 = "joeboxserver" ascii wide
		$proc2 = "joeboxcontrol" ascii wide
	condition:
		any of them
}

rule avdetect_procs
{
	meta:
		Description = "Risk.AVDtc.sm"
		ThreatLevel = "3"

	strings:
		$proc2 = "LMon.exe" ascii wide
		$proc3 = "sagui.exe" ascii wide
		$proc4 = "RDTask.exe" ascii wide
		$proc5 = "kpf4gui.exe" ascii wide
		$proc6 = "ALsvc.exe" ascii wide
		$proc7 = "pxagent.exe" ascii wide
		$proc8 = "fsma32.exe" ascii wide
		$proc9 = "licwiz.exe" ascii wide
		$proc10 = "SavService.exe" ascii wide
		$proc11 = "prevxcsi.exe" ascii wide
		$proc12 = "alertwall.exe" ascii wide
		$proc13 = "livehelp.exe" ascii wide
		$proc14 = "SAVAdminService.exe" ascii wide
		$proc15 = "csi-eui.exe" ascii wide
		$proc16 = "mpf.exe" ascii wide
		$proc17 = "lookout.exe" ascii wide
		$proc18 = "savprogress.exe" ascii wide
		$proc19 = "lpfw.exe" ascii wide
		$proc20 = "mpfcm.exe" ascii wide
		$proc21 = "emlproui.exe" ascii wide
		$proc22 = "savmain.exe" ascii wide
		$proc23 = "outpost.exe" ascii wide
		$proc24 = "fameh32.exe" ascii wide
		$proc25 = "emlproxy.exe" ascii wide
		$proc26 = "savcleanup.exe" ascii wide
		$proc27 = "filemon.exe" ascii wide
		$proc28 = "AntiHook.exe" ascii wide
		$proc29 = "endtaskpro.exe" ascii wide
		$proc30 = "savcli.exe" ascii wide
		$proc31 = "procmon.exe" ascii wide
		$proc32 = "xfilter.exe" ascii wide
		$proc33 = "netguardlite.exe" ascii wide
		$proc34 = "backgroundscanclient.exe" ascii wide
		$proc35 = "Sniffer.exe" ascii wide
		$proc36 = "scfservice.exe" ascii wide
		$proc37 = "oasclnt.exe" ascii wide
		$proc38 = "sdcservice.exe" ascii wide
		$proc39 = "acs.exe" ascii wide
		$proc40 = "scfmanager.exe" ascii wide
		$proc41 = "omnitray.exe" ascii wide
		$proc42 = "sdcdevconx.exe" ascii wide
		$proc43 = "aupdrun.exe" ascii wide
		$proc44 = "spywaretermin" ascii wide
		$proc45 = "atorshield.exe" ascii wide
		$proc46 = "onlinent.exe" ascii wide
		$proc47 = "sdcdevconIA.exe" ascii wide
		$proc48 = "sppfw.exe" ascii wide
		$proc49 = "spywat~1.exe" ascii wide
		$proc50 = "opf.exe" ascii wide
		$proc51 = "sdcdevcon.exe" ascii wide
		$proc52 = "spfirewallsvc.exe" ascii wide
		$proc53 = "ssupdate.exe" ascii wide
		$proc54 = "pctavsvc.exe" ascii wide
		$proc55 = "configuresav.exe" ascii wide
		$proc56 = "fwsrv.exe" ascii wide
		$proc57 = "terminet.exe" ascii wide
		$proc58 = "pctav.exe" ascii wide
		$proc59 = "alupdate.exe" ascii wide
		$proc60 = "opfsvc.exe" ascii wide
		$proc61 = "tscutynt.exe" ascii wide
		$proc62 = "pcviper.exe" ascii wide
		$proc63 = "InstLsp.exe" ascii wide
		$proc64 = "uwcdsvr.exe" ascii wide
		$proc65 = "umxtray.exe" ascii wide
		$proc66 = "persfw.exe" ascii wide
		$proc67 = "CMain.exe" ascii wide
		$proc68 = "dfw.exe" ascii wide
		$proc69 = "updclient.exe" ascii wide
		$proc70 = "pgaccount.exe" ascii wide
		$proc71 = "CavAUD.exe" ascii wide
		$proc72 = "ipatrol.exe" ascii wide
		$proc73 = "webwall.exe" ascii wide
		$proc74 = "privatefirewall3.exe" ascii wide
		$proc75 = "CavEmSrv.exe" ascii wide
		$proc76 = "pcipprev.exe" ascii wide
		$proc77 = "winroute.exe" ascii wide
		$proc78 = "protect.exe" ascii wide
		$proc79 = "Cavmr.exe" ascii wide
		$proc80 = "prifw.exe" ascii wide
		$proc81 = "apvxdwin.exe" ascii wide
		$proc82 = "rtt_crc_service.exe" ascii wide
		$proc83 = "Cavvl.exe" ascii wide
		$proc84 = "tzpfw.exe" ascii wide
		$proc85 = "as3pf.exe" ascii wide
		$proc86 = "schedulerdaemon.exe" ascii wide
		$proc87 = "CavApp.exe" ascii wide
		$proc88 = "privatefirewall3.exe" ascii wide
		$proc89 = "avas.exe" ascii wide
		$proc90 = "sdtrayapp.exe" ascii wide
		$proc91 = "CavCons.exe" ascii wide
		$proc92 = "pfft.exe" ascii wide
		$proc93 = "avcom.exe" ascii wide
		$proc94 = "siteadv.exe" ascii wide
		$proc95 = "CavMud.exe" ascii wide
		$proc96 = "armorwall.exe" ascii wide
		$proc97 = "avkproxy.exe" ascii wide
		$proc98 = "sndsrvc.exe" ascii wide
		$proc99 = "CavUMAS.exe" ascii wide
		$proc100 = "app_firewall.exe" ascii wide
		$proc101 = "avkservice.exe" ascii wide
		$proc102 = "snsmcon.exe" ascii wide
		$proc103 = "UUpd.exe" ascii wide
		$proc104 = "blackd.exe" ascii wide
		$proc105 = "avktray.exe" ascii wide
		$proc106 = "snsupd.exe" ascii wide
		$proc107 = "cavasm.exe" ascii wide
		$proc108 = "blackice.exe" ascii wide
		$proc109 = "avkwctrl.exe" ascii wide
		$proc110 = "procguard.exe" ascii wide
		$proc111 = "CavSub.exe" ascii wide
		$proc112 = "umxagent.exe" ascii wide
		$proc113 = "avmgma.exe" ascii wide
		$proc114 = "DCSUserProt.exe" ascii wide
		$proc115 = "CavUserUpd.exe" ascii wide
		$proc116 = "kpf4ss.exe" ascii wide
		$proc117 = "avtask.exe" ascii wide
		$proc118 = "avkwctl.exe" ascii wide
		$proc119 = "CavQ.exe" ascii wide
		$proc120 = "tppfdmn.exe" ascii wide
		$proc121 = "aws.exe" ascii wide
		$proc122 = "firewall.exe" ascii wide
		$proc123 = "Cavoar.exe" ascii wide
		$proc124 = "blinksvc.exe" ascii wide
		$proc125 = "bgctl.exe" ascii wide
		$proc126 = "THGuard.exe" ascii wide
		$proc127 = "CEmRep.exe" ascii wide
		$proc128 = "sp_rsser.exe" ascii wide
		$proc129 = "bgnt.exe" ascii wide
		$proc130 = "spybotsd.exe" ascii wide
		$proc131 = "OnAccessInstaller.exe" ascii wide
		$proc132 = "op_mon.exe" ascii wide
		$proc133 = "bootsafe.exe" ascii wide
		$proc134 = "xauth_service.exe" ascii wide
		$proc135 = "SoftAct.exe" ascii wide
		$proc136 = "cmdagent.exe" ascii wide
		$proc137 = "bullguard.exe" ascii wide
		$proc138 = "xfilter.exe" ascii wide
		$proc139 = "CavSn.exe" ascii wide
		$proc140 = "VCATCH.EXE" ascii wide
		$proc141 = "cdas2.exe" ascii wide
		$proc142 = "zlh.exe" ascii wide
		$proc143 = "Packetizer.exe" ascii wide
		$proc144 = "SpyHunter3.exe" ascii wide
		$proc145 = "cmgrdian.exe" ascii wide
		$proc146 = "adoronsfirewall.exe" ascii wide
		$proc147 = "Packetyzer.exe" ascii wide
		$proc148 = "wwasher.exe" ascii wide
		$proc149 = "configmgr.exe" ascii wide
		$proc150 = "scfservice.exe" ascii wide
		$proc151 = "zanda.exe" ascii wide
		$proc152 = "authfw.exe" ascii wide
		$proc153 = "cpd.exe" ascii wide
		$proc154 = "scfmanager.exe" ascii wide
		$proc155 = "zerospywarele.exe" ascii wide
		$proc156 = "dvpapi.exe" ascii wide
		$proc157 = "espwatch.exe" ascii wide
		$proc158 = "dltray.exe" ascii wide
		$proc159 = "zerospywarelite_installer.exe" ascii wide
		$proc160 = "clamd.exe" ascii wide
		$proc161 = "fgui.exe" ascii wide
		$proc162 = "dlservice.exe" ascii wide
		$proc163 = "Wireshark.exe" ascii wide
		$proc164 = "sab_wab.exe" ascii wide
		$proc165 = "filedeleter.exe" ascii wide
		$proc166 = "ashwebsv.exe" ascii wide
		$proc167 = "tshark.exe" ascii wide
		$proc168 = "SUPERAntiSpyware.exe" ascii wide
		$proc169 = "firewall.exe" ascii wide
		$proc170 = "ashdisp.exe" ascii wide
		$proc171 = "rawshark.exe" ascii wide
		$proc172 = "vdtask.exe" ascii wide
		$proc173 = "firewall2004.exe" ascii wide
		$proc174 = "ashmaisv.exe" ascii wide
		$proc175 = "Ethereal.exe" ascii wide
		$proc176 = "asr.exe" ascii wide
		$proc177 = "firewallgui.exe" ascii wide
		$proc178 = "ashserv.exe" ascii wide
		$proc179 = "Tethereal.exe" ascii wide
		$proc180 = "NetguardLite.exe" ascii wide
		$proc181 = "gateway.exe" ascii wide
		$proc182 = "aswupdsv.exe" ascii wide
		$proc183 = "Windump.exe" ascii wide
		$proc184 = "nstzerospywarelite.exe" ascii wide
		$proc185 = "hpf_.exe" ascii wide
		$proc186 = "avastui.exe" ascii wide
		$proc187 = "Tcpdump.exe" ascii wide
		$proc188 = "cdinstx.exe" ascii wide
		$proc189 = "iface.exe" ascii wide
		$proc190 = "avastsvc.exe" ascii wide
		$proc191 = "Netcap.exe" ascii wide
		$proc192 = "cdas17.exe" ascii wide
		$proc193 = "invent.exe" ascii wide
		$proc194 = "Netmon.exe" ascii wide
		$proc195 = "fsrt.exe" ascii wide
		$proc196 = "ipcserver.exe" ascii wide
		$proc197 = "CV.exe" ascii wide
		$proc198 = "VSDesktop.exe" ascii wide
		$proc199 = "ipctray.exe" ascii wide
	condition:
		3 of them
}


rule dbgdetect_procs
{
	meta:
		Description = "Risk.DbgDtc.sm"
		ThreatLevel = "3"

	strings:
		$proc1 = "wireshark" nocase ascii wide
		$proc2 = "filemon" nocase ascii wide
		$proc3 = "procexp" nocase ascii wide
		$proc4 = "procmon" nocase ascii wide
		$proc5 = "regmon" nocase ascii wide
		$proc6 = "idag" nocase ascii wide
		$proc7 = "immunitydebugger" nocase ascii wide
		$proc8 = "ollydbg" nocase ascii wide
		$proc9 = "petools" nocase ascii wide

	condition:
		2 of them
}

rule dbgdetect_files
{
	meta:
		Description = "Risk.DbgDtc.sm"
		ThreatLevel = "3"

	strings:
		$file1 = "syserdbgmsg" nocase ascii wide
		$file2 = "syserboot" nocase ascii wide
		$file3 = "SICE" nocase ascii wide
		$file4 = "NTICE" nocase ascii wide
	condition:
		2 of them
}