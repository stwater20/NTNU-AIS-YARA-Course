/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2024-11-21
   Identifier: dataset
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_0a6dc30dcecadd0461f838a2c442c900 {
   meta:
      description = "dataset - file 0a6dc30dcecadd0461f838a2c442c900"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "931e4258cc50ba1d3bf74d862804f071949d2cd9b24dac7721913e66eb69f563"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s2 = "EmbeddedRuntime.exe" fullword ascii
      $s3 = "c:\\Projets\\dotNetProtector5\\EmbeddedRuntime\\Win32\\Release\\EmbeddedRuntime.pdb" fullword ascii
      $s4 = "Torj.exe" fullword wide
      $s5 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC80.CRT\" version=\"8.0.50608.0\" processorArchitecture=\"x86\" publicK" ascii
      $s6 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC80.CRT\" version=\"8.0.50608.0\" processorArchitecture=\"x86\" publicK" ascii
      $s7 = "SmartAssembly.License.Resources.logo.png" fullword ascii
      $s8 = "AppDomain_ProcessExit" fullword ascii
      $s9 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii
      $s10 = "PvLogiciels.dotNetProtector.Runtime" fullword wide
      $s11 = "GetComputerHash" fullword ascii
      $s12 = "ExecuteEmbLockAssembly" fullword ascii
      $s13 = "Descript" fullword ascii
      $s14 = "GetBiosHash" fullword ascii
      $s15 = "GetProductkeyData" fullword ascii
      $s16 = "GetConfigForDemo" fullword ascii
      $s17 = "GetUsbConfig" fullword ascii
      $s18 = "PvLogiciels.dotNetProtector" fullword ascii
      $s19 = "PvLogiciels.dotNetProtector.embedded.netmodule" fullword wide
      $s20 = "SmartAssembly.SmartExceptionsCore.Resources.{logo}.png" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_0a9f5dee6167e66256b3e66a3ed346f0 {
   meta:
      description = "dataset - file 0a9f5dee6167e66256b3e66a3ed346f0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "464829618970f69acdbc78a04f81e8045fecf0a4e59913ed107457cded8eface"
   strings:
      $x1 = "\\cmd.exe /c " fullword ascii
      $s2 = "c:\\windows\\system32\\" fullword ascii
      $s3 = "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\windows\\currentVersion\\run /v %s /t REG_SZ /d \"%s\" /f" fullword ascii
      $s4 = "c:\\windows\\temp\\" fullword ascii
      $s5 = "Facebook Hacking.exe" fullword wide
      $s6 = "c:\\windows\\debug\\" fullword ascii
      $s7 = "%stttbrozzz.bat" fullword ascii
      $s8 = "%stttdelzzz.bat" fullword ascii
      $s9 = "*system32\\" fullword ascii
      $s10 = "bfbflyxt*temp\\" fullword ascii
      $s11 = "%sServer32History.dat" fullword ascii
      $s12 = "kernelfaultEx" fullword ascii
      $s13 = "mamalxyt" fullword ascii
      $s14 = "sourytlx" fullword ascii
      $s15 = "iloverabbit" fullword ascii
      $s16 = "bfbflyxt" fullword ascii
      $s17 = "del \"%s\" /Q" fullword ascii
      $s18 = "E:\\#uP" fullword ascii
      $s19 = "copy \"%s\" \"%s\"" fullword ascii
      $s20 = "if not exist \"%s\" goto done" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_0a263c2a6dba6ce9a480d1edba51c17b {
   meta:
      description = "dataset - file 0a263c2a6dba6ce9a480d1edba51c17b"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "45f55432733413c08d613d3c6c64992aa5659ab8ad49ce1fa59123e95f773b59"
   strings:
      $s1 = ": :$:<:X:\\:`:d:h:l:p:t:x:|:" fullword ascii
      $s2 = "fzHZ'{b^," fullword ascii
      $s3 = "3*3=3i3" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "CCTPKontrolleView" fullword ascii
      $s5 = "??&?+?" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "Fzsk-x/," fullword ascii
      $s7 = " CTPKontrolle" fullword wide
      $s8 = "CTPKontrolle 1.0 " fullword wide
      $s9 = "System" fullword wide /* Goodware String - occured 1819 times */
      $s10 = "OGp888888" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "wwGtwDwwwwwtDDDDw" fullword ascii /* Goodware String - occured 3 times */
      $s12 = "pwwwwppwwww" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "wwGttwGwwwwt" fullword ascii /* Goodware String - occured 3 times */
      $s14 = "wwp0wwww" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "\\. 3oE" fullword ascii
      $s16 = "wwwwpppwww" fullword ascii /* Goodware String - occured 3 times */
      $s17 = "DDGwp8" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "33330p333333" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "wwwttDwwp" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "wwwppwwwp" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule sig_0a4c46978fd70673c98b31458f60fc86 {
   meta:
      description = "dataset - file 0a4c46978fd70673c98b31458f60fc86"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "02157bf54cec981e177074c62c09dd95f5860a90cd50f0b8f6c59456c02cf4ad"
   strings:
      $s1 = "c:\\myapp.exe" fullword ascii
      $s2 = "lgK kh+ =" fullword ascii
      $s3 = "fvAO7\\" fullword ascii
      $s4 = "5sXpEc!" fullword ascii
      $s5 = "tXbm=$V" fullword ascii
      $s6 = "FVQX)B^" fullword ascii
      $s7 = "byCLnbs" fullword ascii
      $s8 = "KQXP*!(_" fullword ascii
      $s9 = "JKppJ_He5" fullword ascii
      $s10 = ",QqSK;\\/$" fullword ascii
      $s11 = ">|SOan3W;=" fullword ascii
      $s12 = "8((IgBc*{L" fullword ascii
      $s13 = "mbFt'`b" fullword ascii
      $s14 = "ujSKI\\" fullword ascii
      $s15 = "@\"dZfhO 7TWt" fullword ascii
      $s16 = "XfvGuf;" fullword ascii
      $s17 = "M@8t^YVJmFL)" fullword ascii
      $s18 = "jAvl?l" fullword ascii
      $s19 = "test 1.0 " fullword wide
      $s20 = "OFHKQY" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule sig_0a425cae056e71a54a496093b6efa1d0 {
   meta:
      description = "dataset - file 0a425cae056e71a54a496093b6efa1d0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "4739fb760495f67547660c3af1a309005a022636e427f4e65e52f724d0d7f232"
   strings:
      $s1 = " RICHED20.DLL " fullword wide
      $s2 = ";PPPPPPPPPPPPPPPP" fullword ascii /* reversed goodware string 'PPPPPPPPPPPPPPPP;' */
      $s3 = "UNSUPPORTEDSAVEFORMATDIALOG(" fullword wide
      $s4 = "(;;;;;;;;;;" fullword ascii /* reversed goodware string ';;;;;;;;;;(' */
      $s5 = "    processorArchitecture=\"x86\"" fullword ascii
      $s6 = "            processorArchitecture=\"x86\"" fullword ascii
      $s7 = "%5;9:;;;;;;" fullword ascii /* hex encoded string 'Y' */
      $s8 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii
      $s9 = "eeeeeeez" fullword ascii
      $s10 = "fffffffffffffffffc" ascii
      $s11 = "eeeeeeey" fullword ascii
      $s12 = "jukdbuh" fullword ascii
      $s13 = "pppvaaa" fullword ascii
      $s14 = ".'%d%% " fullword wide
      $s15 = " MS-DOS (*.txt)" fullword wide
      $s16 = "            version=\"6.0.0.0\"" fullword ascii
      $s17 = "    version=\"1.0.0.0\"" fullword ascii
      $s18 = " Windows 6.0 (*.doc)" fullword wide
      $s19 = " Windows (*.doc)" fullword wide
      $s20 = " Windows 2.0 (*.doc)" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule sig_0a1f17cdcef08079665eef39f6a10fb0 {
   meta:
      description = "dataset - file 0a1f17cdcef08079665eef39f6a10fb0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "79a8a652915145d600e2e2281a252551a55aaf73be2c9fcec3a7da83ab3cdcfd"
   strings:
      $s1 = "C:\\Users\\M\\Desktop\\vc\\" fullword ascii
      $s2 = "myapp.exe" fullword wide
      $s3 = "face.exe" fullword wide
      $s4 = "DSN=%s? DESCRIPTION=TOC support source? DBQ=%s? FIL=MicrosoftAccess? DEFAULTDIR=%s?? " fullword ascii
      $s5 = "\\Release\\lhwy.pdb" fullword ascii
      $s6 = "ecordset" fullword ascii
      $s7 = "\\lhwy.mdb" fullword ascii
      $s8 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
      $s9 = "tkernf" fullword ascii
      $s10 = "CDRecordset" fullword ascii
      $s11 = "fbIn-R" fullword ascii
      $s12 = ",Bpa*DpRich`*Dp" fullword ascii
      $s13 = "VyYuzi@" fullword ascii
      $s14 = "CTRecordset" fullword ascii
      $s15 = ">$>,>4><>D>L>T>`>|>" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "6$6,646@6\\6d6p6" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "uCVVUP;N" fullword ascii
      $s18 = "4$4,444<4D4P4l4t4|4" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "[NO1OBJECT]" fullword wide
      $s20 = "NO1STUDENT]" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule sig_0a47d56e808fae23e2d404d78311c8f3 {
   meta:
      description = "dataset - file 0a47d56e808fae23e2d404d78311c8f3"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "ae1691d9ccf13e4f563fa3b149482358c9aba742e208adb7341a1b4f922e6572"
   strings:
      $s1 = "function ShellExec(const Verb, Filename, Params, WorkingDir: String; const ShowCmd: Integer; const Wait: TExecWait; var ErrorCod" ascii
      $s2 = "function ShellExecAsOriginalUser(const Verb, Filename, Params, WorkingDir: String; const ShowCmd: Integer; const Wait: TExecWait" ascii
      $s3 = "function Exec(const Filename, Params, WorkingDir: String; const ShowCmd: Integer; const Wait: TExecWait; var ResultCode: Integer" ascii
      $s4 = "function ExecAsOriginalUser(const Filename, Params, WorkingDir: String; const ShowCmd: Integer; const Wait: TExecWait; var Resul" ascii
      $s5 = "function CreateShellLink(const Filename, Description, ShortcutTo, Parameters, WorkingDir, IconFilename: String; const IconIndex," ascii
      $s6 = "The setup files are corrupted, or are incompatible with this version of Setup. Please correct the problem or obtain a new copy o" ascii
      $s7 = "function GetSaveFileName(const Prompt: String; var FileName: String; const InitialDirectory, Filter, DefaultExtension: String): " ascii
      $s8 = "function GetOpenFileName(const Prompt: String; var FileName: String; const InitialDirectory, Filter, DefaultExtension: String): " ascii
      $s9 = "fTPPQQ\\_" fullword ascii
      $s10 = "mzciqvk" fullword ascii
      $s11 = " Service Pack " fullword ascii
      $s12 = " ShowCmd: Integer): String;" fullword ascii
      $s13 = "; var ErrorCode: Integer): Boolean;" fullword ascii
      $s14 = "An attempt was made to call the \"CurrentFileName\" function from outside a \"Check\", \"BeforeInstall\" or \"AfterInstall\" eve" ascii
      $s15 = "function CreateInputDirPage(const AfterID: Integer; const ACaption, ADescription, ASubCaption: String; AAppendDir: Boolean; ANew" ascii
      $s16 = "function CreateInputOptionPage(const AfterID: Integer; const ACaption, ADescription, ASubCaption: String; Exclusive, ListBox: Bo" ascii
      $s17 = "Skqyfck" fullword ascii
      $s18 = "function CreateOutputMsgMemoPage(const AfterID: Integer; const ACaption, ADescription, ASubCaption: String; const AMsg: AnsiStri" ascii
      $s19 = "3* d$>o2" fullword ascii
      $s20 = "Ji_%iih%ii_%^1" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_0a126a95f452ac4d704d47d507d7e770 {
   meta:
      description = "dataset - file 0a126a95f452ac4d704d47d507d7e770"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "c768ba36904ba2967e9318905d52bfc81a7d89db3455c76d50013359847ab164"
   strings:
      $s1 = "clrver.exe" fullword wide
      $s2 = "eku> -eku  <OID,OID>      Comma separated enhanced key usage OIDs" fullword wide
      $s3 = " Encoded Data::" fullword wide
      $s4 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s5 = "#Error: Invalid value for -r option" fullword wide
      $s6 = "-----  Signer  [%d] -----" fullword wide
      $s7 = "6Error: Failed to set the enhanced key usage property." fullword wide
      $s8 = "2Error: -7 is invalid for system destination store" fullword wide
      $s9 = "(Error: Failed to open a temporary store" fullword wide
      $s10 = "2-----  Signer [%d] AuthenticatedAttributes  -----" fullword wide
      $s11 = "4-----  Signer [%d] UnauthenticatedAttributes  -----" fullword wide
      $s12 = "SubjectPublicKeyInfo.PublicKey" fullword wide
      $s13 = "*Error: Failed to get the count of signers" fullword wide
      $s14 = "  No Usage Identifiers" fullword wide
      $s15 = "****** Time Invalid CTL" fullword wide
      $s16 = "-----  No Entries  -----" fullword wide
      $s17 = "-----  Entries  -----" fullword wide
      $s18 = "  EnhancedKeyUsage::" fullword wide
      $s19 = "  <EnhancedKeyUsage> " fullword wide
      $s20 = "  <KeyUsage> " fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_0a11e9d86df2b3382436caa79d3a15bd {
   meta:
      description = "dataset - file 0a11e9d86df2b3382436caa79d3a15bd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "a27a93fcca805f4a8e0402577b89594d47b768bc99f760dce8e141490ba824c9"
   strings:
      $s1 = "gkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewu" ascii
      $s2 = "yfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4i" ascii
      $s3 = "jzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhj" ascii
      $s4 = "uhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsd" ascii
      $s5 = "gkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsd" ascii
      $s6 = "dzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiu" ascii
      $s7 = "hsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngk" ascii
      $s8 = "zsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiasweh" ascii
      $s9 = "sdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsdu" ascii
      $s10 = "ehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxd" ascii
      $s11 = "gbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyf" ascii
      $s12 = "sdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuia" ascii
      $s13 = "duyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx" ascii
      $s14 = "jzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzs" ascii
      $s15 = "tsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgk" ascii
      $s16 = "hysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhs" ascii
      $s17 = "swehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjz" ascii
      $s18 = "sdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsd" ascii
      $s19 = "wuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsid" ascii
      $s20 = "jzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysdgbuzsdgkjzsdgkjzdfngjzxdfngkzx4iuhtsidhuiaswehiuhsduyfgasewuhjsdjfzsdzhysd" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule sig_0a630c72ed4eaaf59b5fccadb909dc00 {
   meta:
      description = "dataset - file 0a630c72ed4eaaf59b5fccadb909dc00"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "1eb8b251e4c9d2bae4b904c15654dfa7c78693f257cb5801d74af986ef97fff0"
   strings:
      $s1 = "QQDownload.exe" fullword ascii
      $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x8" ascii
      $s3 = "TNProxy.dll" fullword wide
      $s4 = "DownloadProxy.Downloader.1" fullword wide
      $s5 = "\\tnproxy.dll" fullword wide
      $s6 = "fs_hello.qq.com" fullword ascii
      $s7 = "dlcore.dll" fullword wide
      $s8 = "Extract.dll" fullword wide
      $s9 = "ProgID = s 'DownloadProxy.Downloader.1'" fullword ascii
      $s10 = "CurVer = s 'DownloadProxy.Downloader.1'" fullword ascii
      $s11 = "VersionIndependentProgID = s 'DownloadProxy.Downloader'" fullword ascii
      $s12 = "Tencentdl.exe" fullword wide
      $s13 = "DownloadProxy.Downloader = s 'Downloader Class'" fullword ascii
      $s14 = "DownloadProxy.Downloader.1 = s 'Downloader Class'" fullword ascii
      $s15 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x8" ascii
      $s16 = "fs_report.qq.com" fullword ascii
      $s17 = "d:\\XF Code\\DLPlugins_proj\\branches\\Tencentdl_v109\\Output\\Release\\Tencentdl.pdb" fullword ascii
      $s18 = "\\extract.dll" fullword wide
      $s19 = "\\dlcore.dll" fullword wide
      $s20 = ".?AV?$clone_impl@U?$error_info_injector@V?$basic_filesystem_error@V?$basic_path@V?$basic_string@_WU?$char_traits@_W@std@@V?$allo" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_0a70e777fb042d0b6ffecc7d2203f1f8 {
   meta:
      description = "dataset - file 0a70e777fb042d0b6ffecc7d2203f1f8"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "978207c7983b4b6732add359a3c7a3dfb07d044d6207ce6814fe9d217ee24682"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s3 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:xmp=\"http://ns.adobe.com/xa" ascii
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s5 = "32:00        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii
      $s6 = " Type Descriptor'" fullword ascii
      $s7 = "f:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>" fullword ascii
      $s8 = "DOWNLOAD_GRADIENT_ACTIVE" fullword wide
      $s9 = "DOWNLOAD_GRADIENT_HOVER" fullword wide
      $s10 = "8B\" xmpMM:InstanceID=\"xmp.iid:F8184477427911E1BE2C8FE8570D6C8B\" xmp:CreatorTool=\"Adobe Photoshop CS5 Windows\"> <xmpMM:Deriv" ascii
      $s11 = "16\" xmpMM:InstanceID=\"xmp.iid:02EAA001427A11E1AC92E376DB76A416\" xmp:CreatorTool=\"Adobe Photoshop CS5 Windows\"> <xmpMM:Deriv" ascii
      $s12 = "0/\" xmpMM:OriginalDocumentID=\"xmp.did:EF6BE5E2A841E1118B8EE29349E4B867\" xmpMM:DocumentID=\"xmp.did:F8184478427911E1BE2C8FE857" ascii
      $s13 = "0/\" xmpMM:OriginalDocumentID=\"xmp.did:EF6BE5E2A841E1118B8EE29349E4B867\" xmpMM:DocumentID=\"xmp.did:02EAA002427A11E1AC92E376DB" ascii
      $s14 = "m stRef:instanceID=\"xmp.iid:F36BE5E2A841E1118B8EE29349E4B867\" stRef:documentID=\"xmp.did:EF6BE5E2A841E1118B8EE29349E4B867\"/> " ascii
      $s15 = "LOGO_MASK_200X200" fullword wide
      $s16 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s17 = "LOADING" fullword wide
      $s18 = " Class Hierarchy Descriptor'" fullword ascii
      $s19 = " Base Class Descriptor at (" fullword ascii
      $s20 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule sig_0a300b1bdb83fcf6913a9c6a1d372510 {
   meta:
      description = "dataset - file 0a300b1bdb83fcf6913a9c6a1d372510"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "90d4db65ee18eab573ac28862b9d258179762f9f8367797bdb8bb52c0435d128"
   strings:
      $s1 = "QQDownload.exe" fullword ascii
      $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x8" ascii
      $s3 = "TNProxy.dll" fullword wide
      $s4 = "DownloadProxy.Downloader.1" fullword wide
      $s5 = "\\tnproxy.dll" fullword wide
      $s6 = "fs_hello.qq.com" fullword ascii
      $s7 = "dlcore.dll" fullword wide
      $s8 = "Extract.dll" fullword wide
      $s9 = "ProgID = s 'DownloadProxy.Downloader.1'" fullword ascii
      $s10 = "CurVer = s 'DownloadProxy.Downloader.1'" fullword ascii
      $s11 = "VersionIndependentProgID = s 'DownloadProxy.Downloader'" fullword ascii
      $s12 = "Tencentdl.exe" fullword wide
      $s13 = "d:\\xf code\\dlplugins_proj\\branches\\tencentdl_version\\tencentdl_v112\\output\\release\\Tencentdl.pdb" fullword ascii
      $s14 = "DownloadProxy.Downloader = s 'Downloader Class'" fullword ascii
      $s15 = "DownloadProxy.Downloader.1 = s 'Downloader Class'" fullword ascii
      $s16 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x8" ascii
      $s17 = "fs_report.qq.com" fullword ascii
      $s18 = "\\extract.dll" fullword wide
      $s19 = "\\dlcore.dll" fullword wide
      $s20 = ".?AV?$clone_impl@U?$error_info_injector@V?$basic_filesystem_error@V?$basic_path@V?$basic_string@_WU?$char_traits@_W@std@@V?$allo" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_0a92daa19f2cc77a21cdbf8db6d8bb68 {
   meta:
      description = "dataset - file 0a92daa19f2cc77a21cdbf8db6d8bb68"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "ab097e8b19ec166a2ff65d10ab06a8d572216cee2b0c44ebe183a8cb60b2bae7"
   strings:
      $s1 = "SDevApps.WebServices.CommandSwitch,System.String)\">" fullword ascii
      $s2 = "serviceManager.exe" fullword wide
      $s3 = "Services.CommandRule\">" fullword ascii
      $s4 = "    <member name=\"P:Microsoft.DevApps.WebServices.CommandSwitch.Description\">" fullword ascii
      $s5 = "    <member name=\"P:Microsoft.DevApps.WebServices.CommandSwitch.Value" fullword ascii
      $s6 = "    <member name=\"F:Microsoft.DevApps.WebServices.CommandRule.ValueRequired\">" fullword ascii
      $s7 = "    <member name=\"M:Microsoft.DevApps.WebServices.CommandRule.#ctor(ebServices.CommandSwitch.Name\">" fullword ascii
      $s8 = "    <member name=\"M:Microsoft.DevApps.WebServices.CommandRule.#ctor\">" fullword ascii
      $s9 = "    <member name=\"P:Microsoft.DevApps.WebServices.CommandSwitch.Abbreviation\">" fullword ascii
      $s10 = "    <member name=\"F:Microsoft.DevApps.WebServices.CommandRule.ValueOptional\">" fullword ascii
      $s11 = "r  edSEvbs eMMm.  of- -<-e < m\" " fullword ascii
      $s12 = ")sirci erb.cMF" fullword ascii
      $s13 = "$ ?dme <A<  o- enrc  -le> - eH" fullword ascii
      $s14 = "SeDs.Mlcso /m.bneWStm i" fullword ascii
      $s15 = "lcm.syrm.AWeLs:e.e /CmSi<>tSep.sc/e/.x\"enuM.cnrAc/evtntvro><nswemetvoriic<.nmte .ibelseSi eemhry  mr ebnP<Deonnei oAee\"" fullword ascii
      $s16 = "<nRa=cfmeevDvrmun=SAr eu R.cuC /eR" fullword ascii
      $s17 = "rprwWpecSSn.aae ihe" fullword ascii
      $s18 = "ettm.sSi  " fullword ascii
      $s19 = "oDSr.gcn,MP brrMDoiia i onpe" fullword ascii
      $s20 = "bServices.ArgumentDictionary.IsFixedSize\">" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_0a6b5d3385ed14cc6cea9343e2d64770 {
   meta:
      description = "dataset - file 0a6b5d3385ed14cc6cea9343e2d64770"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "8351d7777625045e81da81e311cf9adf467dd14ddd65638db5807911213357d0"
   strings:
      $s1 = "C:\\vsworkdir\\CSCA1.DLL" fullword ascii
      $s2 = "CSCA1.DLL" fullword ascii
      $s3 = "  xmlns:exif='http://ns.adobe.com/exif/1.0/'>" fullword ascii
      $s4 = "  xmlns:photoshop='http://ns.adobe.com/photoshop/1.0/'>" fullword ascii
      $s5 = "  xmlns:xapMM='http://ns.adobe.com/xap/1.0/mm/'>" fullword ascii
      $s6 = "  xmlns:tiff='http://ns.adobe.com/tiff/1.0/'>" fullword ascii
      $s7 = "  xmlns:pdf='http://ns.adobe.com/pdf/1.3/'>" fullword ascii
      $s8 = "  xmlns:xap='http://ns.adobe.com/xap/1.0/'>" fullword ascii
      $s9 = "OpenSource, coded by Nightmare 2008 " fullword ascii
      $s10 = "C:\\vsworkdir\\shantazh.jpg" fullword wide
      $s11 = "supersecretpass" fullword ascii
      $s12 = "C:\\vsworkdir" fullword ascii
      $s13 = "TCommonDialogX}B" fullword ascii
      $s14 = "  xmlns:dc='http://purl.org/dc/elements/1.1/'>" fullword ascii
      $s15 = " </rdf:Description>" fullword ascii
      $s16 = " <rdf:Description rdf:about='uuid:77f1cf6f-416b-11dd-bb13-d4a8e272ff28'" fullword ascii
      $s17 = ":3:;:\\:d:" fullword ascii /* hex encoded string '=' */
      $s18 = "3!3%3)353" fullword ascii /* hex encoded string '33S' */
      $s19 = "TConversion4" fullword ascii
      $s20 = "gkuqkyt" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_0a92fc841004044f0b71a8206aa4e9f0 {
   meta:
      description = "dataset - file 0a92fc841004044f0b71a8206aa4e9f0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "99662a5ebc3c17cf9f1b54e2053669754dca385a7c7b57c35f87f7413ae205a4"
   strings:
      $s1 = "azaaa.exe" fullword wide
      $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s3 = "My.Computer" fullword ascii
      $s4 = "MyTemplate" fullword ascii
      $s5 = "My.WebServices" fullword ascii
      $s6 = "Microsoft.VisualBasic" fullword ascii /* Goodware String - occured 98 times */
      $s7 = "Create__Instance__" fullword ascii
      $s8 = "Dispose__Instance__" fullword ascii
      $s9 = "My.User" fullword ascii
      $s10 = "MyProject" fullword ascii
      $s11 = "System.Runtime.CompilerServices" fullword ascii /* Goodware String - occured 1950 times */
      $s12 = "System.Reflection" fullword ascii /* Goodware String - occured 2186 times */
      $s13 = "System" fullword ascii /* Goodware String - occured 2567 times */
      $s14 = "C+PC3_I" fullword wide
      $s15 = "c3_c+Pi" fullword wide
      $s16 = "My.Application" fullword ascii
      $s17 = "MyApplication" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_0a9aacbd81bc2500ad27d30fc4c7a650 {
   meta:
      description = "dataset - file 0a9aacbd81bc2500ad27d30fc4c7a650"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "10b21b51baf75113ed865eda25e4da30a27e97ff52914b5af867b3f186e74234"
   strings:
      $s1 = "  <assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"x86\" name=\"FTP\" type=\"win32\"/> " fullword ascii
      $s2 = "  <description>FTP.exe LUA manifest</description> " fullword ascii
      $s3 = "  <!-- Identify the application security requirements. -->" fullword ascii
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s5 = "xhshalj" fullword ascii
      $s6 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s7 = "disconnect" fullword ascii /* Goodware String - occured 30 times */
      $s8 = "COMSPEC" fullword ascii /* Goodware String - occured 247 times */
      $s9 = "status" fullword ascii /* Goodware String - occured 657 times */
      $s10 = "HTDf6u " fullword ascii
      $s11 = "8;8Q8`8f8}8" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "?&?<?C?}?" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "#0;0F0S0u0" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "121M1`1|1" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "9<9@9\\9`9|9" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "5!616E6W6k6" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "6)737K7R7p7{7" fullword ascii /* Goodware String - occured 1 times */
      $s18 = ";0;<;A;r;" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "9-9S9Z9a9s9" fullword ascii /* Goodware String - occured 1 times */
      $s20 = ";3<8<B<J<[<i<u<" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule sig_0a0a36bd0a7c1370bb567674fa68bfcf {
   meta:
      description = "dataset - file 0a0a36bd0a7c1370bb567674fa68bfcf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "f66f73911529568cbb9041be6996575ebaf222b7a026d2e8e73bab70e91526fa"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "ServiceProperties.exe" fullword wide
      $s3 = "nPub.exe" fullword ascii
      $s4 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s6 = "THhVRMiq5bn4fVbdbNIdf3oWyTq0vyLuzYQTDRxxGOOq8d8Rd8GZHIsZcKg8gs4GP2FGFHaJaUXQo8YUUYWxswnqq112uzRXTIaGY2MWi69wvbudwMoHWHXdOYaOQhZk" ascii
      $s7 = "My.Computer" fullword ascii
      $s8 = "MyTemplate" fullword ascii
      $s9 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s10 = "System.Windows.Forms.Form" fullword ascii
      $s11 = "get_ouytghd" fullword ascii
      $s12 = "get_NotifyIcon1" fullword ascii
      $s13 = "get_TextBox1" fullword ascii
      $s14 = "get_PictureBox1" fullword ascii
      $s15 = "get_ProgressBar1" fullword ascii
      $s16 = "# /w9JAs" fullword ascii
      $s17 = "ouytghd" fullword ascii
      $s18 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii
      $s19 = "q:\"fsk" fullword ascii
      $s20 = "My:\\!u" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule sig_0a7bc067437c5684d9a09b66199d8619 {
   meta:
      description = "dataset - file 0a7bc067437c5684d9a09b66199d8619"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "27c172e2f10fec3be812d5007587e18d163d42c04bd34accfe791a54ab639a69"
   strings:
      $s1 = "System.Core, Version=2.0.5.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e" fullword wide
      $s2 = "FLVGuncelle.exe" fullword wide
      $s3 = "CreateDecryptor" fullword wide
      $s4 = "CreateEncryptor" fullword wide
      $s5 = "{290f4baa-f6f6-4183-b3aa-036fa8fd6e66}, PublicKeyToken=3e56350693f7355e" fullword wide
      $s6 = "System.Security.Cryptography.RijndaelManaged" fullword wide
      $s7 = "! \" # $ % & ' ( ) * + , - " fullword wide
      $s8 = "Wrong Header Signature" fullword wide
      $s9 = "Unknown Header" fullword wide
      $s10 = "SmartAssembly.Attributes" fullword ascii
      $s11 = "includeVersion" fullword ascii
      $s12 = "FLVGuncelle.Properties" fullword ascii
      $s13 = "DownloadFileAsync" fullword ascii /* Goodware String - occured 19 times */
      $s14 = "LoadFile" fullword ascii /* Goodware String - occured 101 times */
      $s15 = "Completed" fullword ascii /* Goodware String - occured 113 times */
      $s16 = "process" fullword ascii /* Goodware String - occured 171 times */
      $s17 = "Program" fullword ascii /* Goodware String - occured 194 times */
      $s18 = "CurrentUser" fullword ascii /* Goodware String - occured 204 times */
      $s19 = "System.Security.Cryptography" fullword ascii /* Goodware String - occured 305 times */
      $s20 = "MemoryStream" fullword ascii /* Goodware String - occured 420 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule sig_0a2150c408e22b12d329c9700448a8b0 {
   meta:
      description = "dataset - file 0a2150c408e22b12d329c9700448a8b0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "ef67975c209b2f7dab21da1ce2a8e7a837df4000060ade5c887e81c399d94015"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s2 = "<dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" p" ascii
      $s3 = "s-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></reque" ascii
      $s4 = "ecomsvcs.dll" fullword wide
      $s5 = "CVLMb4aSp6DUvueRYZTDQ0sKCV8xHGawR3GZ6bZZpHr2iWXXd6AHe1ouWdYaoy0ztWs1em1IPNufOq3DLLUiy4iflbcUZ0qA6yXWJ8xFr6jp80pxsyMDHaKCXPpBibyr" ascii
      $s6 = "CVLMb4aSp6DUvueRYZTDQ0sKCV8xHGawR3GZ6bZZpHr2iWXXd6AHe1ouWdYaoy0ztWs1em1IPNufOq3DLLUiy4iflbcUZ0qA6yXWJ8xFr6jp80pxsyMDHaKCXPpBibyr" ascii
      $s7 = "A1nbOYBNJhIvIOpijaaRSXMgZlrKyHnxdxmfrApnGshzemQ6NGsdq66NIxM2kxjy7W5ThwYwEzwGz0Uf7jEz4vFPGkrbINUrxluLRwXUH3mncjJrWkhlUKm9xoAeJ1Yi" ascii
      $s8 = "d3QK4agOpW7UJGh67iBaAMdeY3A29W7WYdOeZhsP764u6ivtPTt6OVo9UcGKW9waNVhUUdRRbFgZVbHayXc6qg1XJ5LZ6BSz82kjGP4fvU27uWhlJTEKcbB8cowg3mff" ascii
      $s9 = "SdXn8cLKT5r3VyIa5ZlJtGtHGey9BKOtzViEMiupmkQYdHu4iAQitUcZzXzxkTNt9BFXA5AHJmAlxUFT4CY7xB8E7mLPsWofotbNKwWvF8maIgdWPDx9EGL9irGakZvZ" ascii
      $s10 = "3Lp9R5vbIXtzd8eOz8isEfsvlGs8ZGzTrUgSVVyfAuqhvVzImPbyUqsEal05qkVVpjLEsNYCEjAGA0neQAE79HfRe7L77Uwfj3CeR7zmYkMSVequiQyInkyAjpQJKVkC" ascii
      $s11 = "NEzgs0fb5sFtXFw2X2mDn9OUbhNafr7uZUTC9NylyD3JsFexWnJDjaVOlrvzPnPqBdxLW6gnDQDDj8LmOPDsEROzd2622kMii0IBzxDxYhXvoLZQc29OqnDRLBQKg2Th" ascii
      $s12 = "PVRtxIu4jmwOpGSiG8LKqiQKeAfntdR3QBfEG4zs1eKOzMEUxiggAQs6Epd9niZriOFfj6JYlrMrY9DVPYXYtQEC9ho5zupsbqPC8pHHNd4qoGDvCdWz9l6u8ZDvxkcz" ascii
      $s13 = "rfRTaiCkgrJ9WJbe0tkTBHHDOa2o2cpR2mqHfZ1PS9FKrujLjoWnyuEZ5atn1xRQg99f1VDnIzyg1yoLXMsWuXpvchh2Qw4DT4Mcs52G2FPD8Ky2Gce0eoGdgmVhbFAk" ascii
      $s14 = "NEzgs0fb5sFtXFw2X2mDn9OUbhNafr7uZUTC9NylyD3JsFexWnJDjaVOlrvzPnPqBdxLW6gnDQDDj8LmOPDsEROzd2622kMii0IBzxDxYhXvoLZQc29OqnDRLBQKg2Th" ascii
      $s15 = "SCPaf2vc2Dh6b1HJXQG1DGGYBT0BgneVsEi556waOdQJFcIDyvSK8P9jeAZToclmlNcfcXwdLdYAaCVzI81AAoieRatnbWsNZVguiFVQkyCojUSuzXTALzQpg3vY2IOe" ascii
      $s16 = "E1II3n3NgPO081R0UfItucO9vBlXqnKZE78W2iv3taG9fm9Stuo0Os2cNa4WG7KBgd4Kry2pLqWDMrNyJhYqXLrZzepRQw4sC7HqcpLJH5qYi1nuXZxvRtSNZWgBfj5x" ascii
      $s17 = "d3QK4agOpW7UJGh67iBaAMdeY3A29W7WYdOeZhsP764u6ivtPTt6OVo9UcGKW9waNVhUUdRRbFgZVbHayXc6qg1XJ5LZ6BSz82kjGP4fvU27uWhlJTEKcbB8cowg3mff" ascii
      $s18 = "rfRTaiCkgrJ9WJbe0tkTBHHDOa2o2cpR2mqHfZ1PS9FKrujLjoWnyuEZ5atn1xRQg99f1VDnIzyg1yoLXMsWuXpvchh2Qw4DT4Mcs52G2FPD8Ky2Gce0eoGdgmVhbFAk" ascii
      $s19 = "A4bnNwzWfi8Gjg6YwKgEBLukcms8AZPpu5qrd0KcvYWPVt3t6mCHrC6EeHMogDVersu2GQfyiZzaPVOan3ZiFsZqT9qaNQogJhloRnA4j7s5OMmOJLVr8RceGS0UC3i3" ascii
      $s20 = "bSeeSDkFltWYTtyDrh4AhmpTTT6E8ecTfxlzqKFy3zxFeagCOsXRBtjk9AxZjNgwWecjo9mcQsKXodJtEciuMJbN6g0mw9MuVariXao6ILI1EkFtwEDwwgNMzgaVRKbt" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule sig_0a4a60ea3eef142719e18308ead9ad20 {
   meta:
      description = "dataset - file 0a4a60ea3eef142719e18308ead9ad20"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "82f76ad327c37822a8c15f195258ea27a76ac106fab7b7560c7e1d1b9a389849"
   strings:
      $s1 = "C:\\DOCUME~1\\THEYOU~1\\LOCALS~1\\Temp\\Temporary Directory 1 for Resume_LinkedIn[2].zip\\Resume_LinkedIn.exe" fullword wide
      $s2 = "C:\\NVfshtih.exe" fullword wide
      $s3 = "C:\\Atoraqrr.exe" fullword wide
      $s4 = "C:\\f7m1PLhV.exe" fullword wide
      $s5 = "C:\\1bfElBg1.exe" fullword wide
      $s6 = "C:\\Y30QoIJd.exe" fullword wide
      $s7 = "C:\\0FnvulbP.exe" fullword wide
      $s8 = "C:\\hlNVxYYd.exe" fullword wide
      $s9 = "C:\\bHCu1Aou.exe" fullword wide
      $s10 = "C:\\gK2lHufn.exe" fullword wide
      $s11 = "C:\\eHsvONwr.exe" fullword wide
      $s12 = "C:\\Cjwm2bqT.exe" fullword wide
      $s13 = "C:\\4Txjwd8j.exe" fullword wide
      $s14 = "C:\\981XuGKL.exe" fullword wide
      $s15 = "C:\\iZDbRaqP.exe" fullword wide
      $s16 = "C:\\vakLTat1.exe" fullword wide
      $s17 = "C:\\3T2pScwu.exe" fullword wide
      $s18 = "C:\\cXPiH9ZJ.exe" fullword wide
      $s19 = "C:\\xKjN4Lja.exe" fullword wide
      $s20 = "C:\\z0LCRXVG.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      8 of them
}

rule sig_0a2d783ce96d3243f13012879dc2bc50 {
   meta:
      description = "dataset - file 0a2d783ce96d3243f13012879dc2bc50"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "501147525593dd439ffae29bdc613ceffa9e12efb0b628cf42633e8f0288323c"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s2 = "<dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" p" ascii
      $s3 = "s-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></reque" ascii
      $s4 = "1comsvcs.dll" fullword wide
      $s5 = "uiscan.exe" fullword wide
      $s6 = "0A7UcxCIG955oZgDmRDAvXtB8ATGBEiwSEh9QQXaa6KTHi8FHHsXHOjF2PeESiNmxJ6mr4iJGRy2q6ROIpXdmgpbiIm8XSNAp4AYu2XzKItWg0DXXrpPM9U6FoghnYMs" ascii
      $s7 = "fHaQSUyBJZftmIQfddJkn1Sy6YiVFTLAMx6lNGIvrFuBeBNkPtRPISPp3dKnjBc0656O40UGLvmfePhXOpoE9rhrmKL8CNXYfweYlgKYeOTkKYAu4qEdfEVGQVKtqdHi" ascii
      $s8 = "YK3UfEwNtV2bDhRJlZoCvhBk5Y7nsbIUAQqsSRNLLXnyo8jiaXsldkp5OnxnuSvSV7H1dyGpQA3gbHujeVhP0HItDPDNDRhuJpH7yMoX7LmTdvZsz0mSYzWi9LmTVUFX" ascii
      $s9 = "0A7UcxCIG955oZgDmRDAvXtB8ATGBEiwSEh9QQXaa6KTHi8FHHsXHOjF2PeESiNmxJ6mr4iJGRy2q6ROIpXdmgpbiIm8XSNAp4AYu2XzKItWg0DXXrpPM9U6FoghnYMs" ascii
      $s10 = "EiyHzWkLSyj7hTAothDmR3UBjPdkCGJDrXeobpZpNGqycI5BsLLxDKTfPUk76BJIBjqcU19QnYH0dRAVUMHqPMYOb6fEvi3Hef0Vwyj275tzXDTIizA8n3QGWWO9Rv5e" ascii
      $s11 = "rrO30g5baKYTtkKaZAuAUGRgrdw8cwJy056HNTz08USTMOrJjfL9iHUsWjUHcmMNa9tTlvwvLhyecldiqO1jMGsVuMmKVf3VcnZF4AZHcWCJdVSCKCWab7mlljHSeR9a" ascii
      $s12 = "rK0RpHnFzQIdsNK0qoceDNlEh8CdTjiuiNDX6JFyOnXI39i1LN9wbzIaTu1CvP5sKKMZYOMD7a9lRsBn407ROtFjp4vHXussh1tWS0LRGUNYABIkVJuC0mMtLz1l6tkr" ascii
      $s13 = "rrO30g5baKYTtkKaZAuAUGRgrdw8cwJy056HNTz08USTMOrJjfL9iHUsWjUHcmMNa9tTlvwvLhyecldiqO1jMGsVuMmKVf3VcnZF4AZHcWCJdVSCKCWab7mlljHSeR9a" ascii
      $s14 = "YK3UfEwNtV2bDhRJlZoCvhBk5Y7nsbIUAQqsSRNLLXnyo8jiaXsldkp5OnxnuSvSV7H1dyGpQA3gbHujeVhP0HItDPDNDRhuJpH7yMoX7LmTdvZsz0mSYzWi9LmTVUFX" ascii
      $s15 = "rSOWtwL3ntKeFLvzicg5XiNRDCYXYLulWgWggaglgGU3D2VpP1H3VWsBCBP2tZQZeRKhghEg7HYyhsJPIaVGz1CYBkyXr9LXEVtPwPL9DT9knBnGY5yP8ALPfqycBnvM" ascii
      $s16 = "xtGV0D1sU8kF8I2FSlf0lzNefmWmOHEAuJeA3etltFeeiOsSHjkS2zhaVKI7pBw8UNnGdpIAZixQChBqWoaHcNjvbVR9zgsFWZu5sFPZksViGIHGeLrGymp5X7RyW7O2" ascii
      $s17 = "EiyHzWkLSyj7hTAothDmR3UBjPdkCGJDrXeobpZpNGqycI5BsLLxDKTfPUk76BJIBjqcU19QnYH0dRAVUMHqPMYOb6fEvi3Hef0Vwyj275tzXDTIizA8n3QGWWO9Rv5e" ascii
      $s18 = "orArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\"/></dependentAssembly></dependency><trustInfo xmlns=\"urn" ascii
      $s19 = "rSOWtwL3ntKeFLvzicg5XiNRDCYXYLulWgWggaglgGU3D2VpP1H3VWsBCBP2tZQZeRKhghEg7HYyhsJPIaVGz1CYBkyXr9LXEVtPwPL9DT9knBnGY5yP8ALPfqycBnvM" ascii
      $s20 = "iDLVcIrCkENFMZlMDDDHHUKf9EFw7F8Qkb2b101ZyhEEMxmsdz3839LTWDw9mKy6z1LVbAQ29ipnPrrGIgg6nUHCSlLFvwMr83" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule sig_0a34e63d87175408024d8d9ed1aad320 {
   meta:
      description = "dataset - file 0a34e63d87175408024d8d9ed1aad320"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "e0300019ea5b5c82297675868ac99a9751e7e86fd386de71762800dda9a4f41f"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s2 = "<dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" p" ascii
      $s3 = "s-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></reque" ascii
      $s4 = "1comsvcs.dll" fullword wide
      $s5 = "uiscan.exe" fullword wide
      $s6 = "0A7UcxCIG955oZgDmRDAvXtB8ATGBEiwSEh9QQXaa6KTHi8FHHsXHOjF2PeESiNmxJ6mr4iJGRy2q6ROIpXdmgpbiIm8XSNAp4AYu2XzKItWg0DXXrpPM9U6FoghnYMs" ascii
      $s7 = "fHaQSUyBJZftmIQfddJkn1Sy6YiVFTLAMx6lNGIvrFuBeBNkPtRPISPp3dKnjBc0656O40UGLvmfePhXOpoE9rhrmKL8CNXYfweYlgKYeOTkKYAu4qEdfEVGQVKtqdHi" ascii
      $s8 = "YK3UfEwNtV2bDhRJlZoCvhBk5Y7nsbIUAQqsSRNLLXnyo8jiaXsldkp5OnxnuSvSV7H1dyGpQA3gbHujeVhP0HItDPDNDRhuJpH7yMoX7LmTdvZsz0mSYzWi9LmTVUFX" ascii
      $s9 = "0A7UcxCIG955oZgDmRDAvXtB8ATGBEiwSEh9QQXaa6KTHi8FHHsXHOjF2PeESiNmxJ6mr4iJGRy2q6ROIpXdmgpbiIm8XSNAp4AYu2XzKItWg0DXXrpPM9U6FoghnYMs" ascii
      $s10 = "EiyHzWkLSyj7hTAothDmR3UBjPdkCGJDrXeobpZpNGqycI5BsLLxDKTfPUk76BJIBjqcU19QnYH0dRAVUMHqPMYOb6fEvi3Hef0Vwyj275tzXDTIizA8n3QGWWO9Rv5e" ascii
      $s11 = "rrO30g5baKYTtkKaZAuAUGRgrdw8cwJy056HNTz08USTMOrJjfL9iHUsWjUHcmMNa9tTlvwvLhyecldiqO1jMGsVuMmKVf3VcnZF4AZHcWCJdVSCKCWab7mlljHSeR9a" ascii
      $s12 = "rK0RpHnFzQIdsNK0qoceDNlEh8CdTjiuiNDX6JFyOnXI39i1LN9wbzIaTu1CvP5sKKMZYOMD7a9lRsBn407ROtFjp4vHXussh1tWS0LRGUNYABIkVJuC0mMtLz1l6tkr" ascii
      $s13 = "rrO30g5baKYTtkKaZAuAUGRgrdw8cwJy056HNTz08USTMOrJjfL9iHUsWjUHcmMNa9tTlvwvLhyecldiqO1jMGsVuMmKVf3VcnZF4AZHcWCJdVSCKCWab7mlljHSeR9a" ascii
      $s14 = "YK3UfEwNtV2bDhRJlZoCvhBk5Y7nsbIUAQqsSRNLLXnyo8jiaXsldkp5OnxnuSvSV7H1dyGpQA3gbHujeVhP0HItDPDNDRhuJpH7yMoX7LmTdvZsz0mSYzWi9LmTVUFX" ascii
      $s15 = "rSOWtwL3ntKeFLvzicg5XiNRDCYXYLulWgWggaglgGU3D2VpP1H3VWsBCBP2tZQZeRKhghEg7HYyhsJPIaVGz1CYBkyXr9LXEVtPwPL9DT9knBnGY5yP8ALPfqycBnvM" ascii
      $s16 = "xtGV0D1sU8kF8I2FSlf0lzNefmWmOHEAuJeA3etltFeeiOsSHjkS2zhaVKI7pBw8UNnGdpIAZixQChBqWoaHcNjvbVR9zgsFWZu5sFPZksViGIHGeLrGymp5X7RyW7O2" ascii
      $s17 = "EiyHzWkLSyj7hTAothDmR3UBjPdkCGJDrXeobpZpNGqycI5BsLLxDKTfPUk76BJIBjqcU19QnYH0dRAVUMHqPMYOb6fEvi3Hef0Vwyj275tzXDTIizA8n3QGWWO9Rv5e" ascii
      $s18 = "orArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\"/></dependentAssembly></dependency><trustInfo xmlns=\"urn" ascii
      $s19 = "rSOWtwL3ntKeFLvzicg5XiNRDCYXYLulWgWggaglgGU3D2VpP1H3VWsBCBP2tZQZeRKhghEg7HYyhsJPIaVGz1CYBkyXr9LXEVtPwPL9DT9knBnGY5yP8ALPfqycBnvM" ascii
      $s20 = "iDLVcIrCkENFMZlMDDDHHUKf9EFw7F8Qkb2b101ZyhEEMxmsdz3839LTWDw9mKy6z1LVbAQ29ipnPrrGIgg6nUHCSlLFvwMr83" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule sig_0a068e86705d34ce3ff15fd9fbd33250 {
   meta:
      description = "dataset - file 0a068e86705d34ce3ff15fd9fbd33250"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "61f27cad5d0f264988c3dbca52db8a4f8a4b9421c1d399c852cb32742f1ef477"
   strings:
      $s1 = "myubhpcidyehepjsenpxflenvblbxpxjpesxrmwssrhxuhuprwhxbhababxialnheqajeyxvlpxaeljpkwdjgfaigmlvtlljgfsbgsafmediccsdxcomcnjuybunvios" ascii
      $s2 = "kpejpqultcomiujtnpkosggftyiflaolayuobsvirvtefmblvaoypjqoekfooqcvopmfldwvnshfrskqttonklbhcfpmteylyuebmwoajtcwwohfajsaeixvbyqgxfmu" ascii
      $s3 = "jfnbdqagigqwcvbjfwuaushxopgwitewjfviehkeihtyrahtsulwusbojgbtlltjndwdgltotqrffgcqilrfttxdppekosyrnxcnlaqbqqwufqbmywclsefnjtqajnbm" ascii
      $s4 = "eoolqymdkdyecxbefnrrxsghxbbmmgxtwgcvkibwrtosodsyndouvfyipkvmccxbygwliifwiltxorslsxrhnmjtxnaytxjeedghhhnmjevblqbuvasbfrtsonrmfqlx" ascii
      $s5 = "rnxlhdwmrt" fullword ascii
      $s6 = "itcfulvkjwlqibb" fullword ascii
      $s7 = "ylabpiwvimmrk" fullword ascii
      $s8 = "sosydumebybu" fullword ascii
      $s9 = "chhxrjtld" fullword ascii
      $s10 = "xlcrqdeqmcgbvqfyuefdsaiappqyteyallfknqydkcrrcvwjbkcejjvybruhqgmigofkmnjvmwccuensxhgmolaplvdlqrpwykteloociwarrsaqaowsfvdcvrwwpflr" ascii
      $s11 = "jvjlouvsjxfgcrw" fullword ascii
      $s12 = "cycvwvko" fullword ascii
      $s13 = "lbhvpadvlbjinbgaliqhjpkyeeopyovuthkvrnsmbplvuiwwuhjcnvwecnagvrxnvehialypuafvtjnwmvpxbxgmbmaudiatwylicckwfvmbgrsbstuwsljeeyucqdlm" ascii
      $s14 = "dqufheuywatysrsgmfeetqcgnvgacgedrewobxixgticucyunhjxibsfrnoiltklgiixsspsqdmwsrdpkkaojyuuhejdntquufpymnfjcqdqhqswvclxgtjkbrumwers" ascii
      $s15 = "wnwoailma" fullword ascii
      $s16 = "hablamax" fullword wide
      $s17 = "WELDQKMGUF" fullword ascii
      $s18 = "CCERVSIWXODK" fullword ascii
      $s19 = "KGOXLMVQRBPKWPV" fullword ascii
      $s20 = "Ocotahy" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule sig_0a4b21a7901a930c8e9f7e5f06df1430 {
   meta:
      description = "dataset - file 0a4b21a7901a930c8e9f7e5f06df1430"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "a0dbbaaaa92f75537cffbc99f941b5e5332c8ae7818ce67aefec870b1d20db7c"
   strings:
      $s1 = "Nuw:\"Fw" fullword ascii
      $s2 = "7AVH:\"N" fullword ascii
      $s3 = "MNzfTp" fullword ascii
      $s4 = "q@SPY|" fullword ascii
      $s5 = "V+GetX" fullword ascii
      $s6 = "ivNEHJ3" fullword ascii
      $s7 = "} -pK?" fullword ascii
      $s8 = "o6\":* J" fullword ascii
      $s9 = "l1%A%h" fullword ascii
      $s10 = "_+ 2@w" fullword ascii
      $s11 = ":4J%Dw%" fullword ascii
      $s12 = "w- 5 mw" fullword ascii
      $s13 = "IKBq7%7" fullword ascii
      $s14 = "QLoSI!" fullword ascii
      $s15 = "dOwS`fb." fullword ascii
      $s16 = "Ehho?g." fullword ascii
      $s17 = "pUfTF)MB" fullword ascii
      $s18 = "wFphAPx" fullword ascii
      $s19 = "ypYll;5" fullword ascii
      $s20 = "v/I.GRh" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_0a81dd82bbcb345ef8e555c955308150 {
   meta:
      description = "dataset - file 0a81dd82bbcb345ef8e555c955308150"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "596f08fcaa5ececf95c1eabbc3b161b4ff3f00e30150984942c706c46e5532ad"
   strings:
      $s1 = "# ~BFW" fullword ascii
      $s2 = "bwvWsK2" fullword ascii
      $s3 = "jnfYMSf8md" fullword ascii
      $s4 = "qGFzq\"Frq" fullword ascii
      $s5 = "7YipF6Wt" fullword ascii
      $s6 = "B\\QSBTQ;B@e'B)," fullword ascii
      $s7 = "edTuJmT" fullword ascii
      $s8 = ")^FgERFkAFF" fullword ascii
      $s9 = "[waAMEqk" fullword ascii
      $s10 = "XDMAbL;2yXdl_" fullword ascii
      $s11 = "sy>?xqMtsy>DpW" fullword ascii
      $s12 = "FeSX_1F" fullword ascii
      $s13 = "hQLsheS" fullword ascii
      $s14 = "fPTvheUr" fullword ascii
      $s15 = "*XWUy+\"&y" fullword ascii
      $s16 = "haa;hrelYku" fullword ascii
      $s17 = "K~cIK~cIKnc9Knc\\n{cJh}c" fullword ascii
      $s18 = "{vvFI\\Bz" fullword ascii
      $s19 = "o|KpeAw;e" fullword ascii
      $s20 = "YhFH7q*" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_0a78b63e566e8ce4f986081f553fc800 {
   meta:
      description = "dataset - file 0a78b63e566e8ce4f986081f553fc800"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "30ba02c35528eac0ddd7f1ed9ad72eddc34eda4a76abe2509e4d7fa7e6d7cad2"
   strings:
      $x1 = "C:\\Users\\JACKLY~1\\AppData\\Local\\Temp\\Rar$DIa0.353\\Document-83265.scr" fullword wide
      $s2 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker" ascii
      $s3 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s4 = "C:\\e7KKdHjq.exe" fullword wide
      $s5 = "C:\\ZlVe5mOC.exe" fullword wide
      $s6 = "C:\\HEwJ29qM.exe" fullword wide
      $s7 = "C:\\Jq6QHxp8.exe" fullword wide
      $s8 = "C:\\mXrjEgIg.exe" fullword wide
      $s9 = "C:\\7p15wNcu.exe" fullword wide
      $s10 = "C:\\TbAWUg2R.exe" fullword wide
      $s11 = "C:\\UBLu5gSC.exe" fullword wide
      $s12 = "C:\\VcFRVZvB.exe" fullword wide
      $s13 = "lister.exe" fullword wide
      $s14 = "C:\\G51OLZ_b.exe" fullword wide
      $s15 = "C:\\yw6ge4x1.exe" fullword wide
      $s16 = "C:\\Ge7Jo7dV.exe" fullword wide
      $s17 = "&5@,@=A5e" fullword ascii /* hex encoded string 'Z^' */
      $s18 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s19 = "SqDLL&" fullword ascii
      $s20 = "Manocle" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*) and 4 of them
}

rule sig_0a4d261ac81f561af3730a8a0db4f090 {
   meta:
      description = "dataset - file 0a4d261ac81f561af3730a8a0db4f090"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "8d2914279fed4f0ab577592a9ee71dd2547c6d68eac40c62a5d05d7cb5024d8c"
   strings:
      $x1 = "ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f /t REG_SZ /v COM_LOADER /d \"\\\\.\\%sProgram Files\\PDF_Reader" ascii
      $x2 = "ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f /t REG_SZ /v COM_LOADER /d \"\\\\.\\%sProgram Files\\PDF_Reader" ascii
      $x3 = "c:\\windows\\system32\\syssh32.dll" fullword ascii
      $x4 = "abletFpndZvKgnrhqndmGhhltehmphrhdbWraGJiebvmgWUhekTeiUUpxveaSVhJSbCHkbpTKZWAgHeygnOtOhkHHpqbZdaWkAnWTJinbFvhrZthvATGilbxqZdaFndg" ascii
      $x5 = "/123456c:\\WINDOWS\\system32\\shell32.dll" fullword wide
      $x6 = "\\\\.\\%sProgram Files\\PDF_Reader\\bin\\COM7.EXE" fullword ascii
      $x7 = "C:\\RECYCLER\\bilbilal.exe" fullword ascii
      $s8 = "\\\\.\\%sProgram Files\\PDF_Reader\\PDF_Reader.exe" fullword ascii
      $s9 = "PDFReader.exe" fullword wide
      $s10 = "bilbilal.exe" fullword ascii
      $s11 = "com7.exe" fullword ascii
      $s12 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; ar; rv:1.9.0.5) Gecko/2008120122 Firefox/3.0.5" fullword ascii
      $s13 = "PDF Reader Launcher.exe" fullword ascii
      $s14 = "PDF_Reader FULL.exe" fullword ascii
      $s15 = "COM7.EXE" fullword ascii
      $s16 = "ashcv.exe" fullword ascii
      $s17 = "MusicMP3.exe" fullword wide
      $s18 = ".\\RECYCLER\\bilbilal.exe" fullword wide
      $s19 = "www.ibayme.eb2a.com" fullword ascii
      $s20 = "\\\\.\\%sProgram Files\\PDF_Reader\\bin\\" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule sig_0a97c755f665666b5b54578cee795c30 {
   meta:
      description = "dataset - file 0a97c755f665666b5b54578cee795c30"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "5ed2cff50ad83f8269f17dafd41bda39148edc82b53c55b832862bfce1e60e50"
   strings:
      $x1 = "ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f /t REG_SZ /v COM_LOADER /d \"\\\\.\\%sProgram Files\\PDF_Reader" ascii
      $x2 = "ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f /t REG_SZ /v COM_LOADER /d \"\\\\.\\%sProgram Files\\PDF_Reader" ascii
      $x3 = "c:\\windows\\system32\\syssh32.dll" fullword ascii
      $x4 = "/123456c:\\WINDOWS\\system32\\shell32.dll" fullword wide
      $x5 = "\\\\.\\%sProgram Files\\PDF_Reader\\bin\\COM7.EXE" fullword ascii
      $x6 = "C:\\RECYCLER\\bilbilal.exe" fullword ascii
      $s7 = "\\\\.\\%sProgram Files\\PDF_Reader\\PDF_Reader.exe" fullword ascii
      $s8 = "TyhVoeredcMgOnqCMJhgogrhSSodZpdFggqmVMitgVtTgWUsTTnCnhdTipehhtHdWZiHHklMqblVHMWipeddpWnphTfrnjmbqhjpnhMdSTeGkSrOvhdfmKJbGdhTScHh" ascii
      $s9 = "bilbilal.exe" fullword ascii
      $s10 = "com7.exe" fullword ascii
      $s11 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; ar; rv:1.9.0.5) Gecko/2008120122 Firefox/3.0.5" fullword ascii
      $s12 = "PDF Reader Launcher.exe" fullword ascii
      $s13 = "PDF_Reader FULL.exe" fullword ascii
      $s14 = "COM7.EXE" fullword ascii
      $s15 = "ashcv.exe" fullword ascii
      $s16 = "MusicMP3.exe" fullword wide
      $s17 = ".\\RECYCLER\\bilbilal.exe" fullword wide
      $s18 = "www.ibayme.eb2a.com" fullword ascii
      $s19 = "\\\\.\\%sProgram Files\\PDF_Reader\\bin\\" fullword ascii
      $s20 = "@kernel32.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule sig_0a83e60a97597440fc5c22d6a0bdf040 {
   meta:
      description = "dataset - file 0a83e60a97597440fc5c22d6a0bdf040"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "78f0e9ae174802dc4e102d6a3430e9bd399d69038105ea1e926d3973b3b9a8de"
   strings:
      $x1 = "ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f /t REG_SZ /v COM_LOADER /d \"\\\\.\\%sProgram Files\\PDF_Reader" ascii
      $x2 = "ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f /t REG_SZ /v COM_LOADER /d \"\\\\.\\%sProgram Files\\PDF_Reader" ascii
      $x3 = "c:\\windows\\system32\\syssh32.dll" fullword ascii
      $x4 = "/123456c:\\WINDOWS\\system32\\shell32.dll" fullword wide
      $x5 = "\\\\.\\%sProgram Files\\PDF_Reader\\bin\\COM7.EXE" fullword ascii
      $x6 = "C:\\RECYCLER\\bilbilal.exe" fullword ascii
      $s7 = "TyhVoeredcMgOnqCMJhgogrhSSodZpdFggqmVMitgVtTgWUsTTnCnhdTipehhtHdWZiHHklMqblVHMWipeddpWnphTfrnjmbqhjpnhMdSTeGkSrOvhdfmKJbGdhTScHh" ascii
      $s8 = "\\\\.\\%sProgram Files\\PDF_Reader\\PDF_Reader.exe" fullword ascii
      $s9 = "bilbilal.exe" fullword ascii
      $s10 = "com7.exe" fullword ascii
      $s11 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; ar; rv:1.9.0.5) Gecko/2008120122 Firefox/3.0.5" fullword ascii
      $s12 = "PDF Reader Launcher.exe" fullword ascii
      $s13 = "PDF_Reader FULL.exe" fullword ascii
      $s14 = "COM7.EXE" fullword ascii
      $s15 = "ashcv.exe" fullword ascii
      $s16 = "MusicMP3.exe" fullword wide
      $s17 = ".\\RECYCLER\\bilbilal.exe" fullword wide
      $s18 = "www.ibayme.eb2a.com" fullword ascii
      $s19 = "\\\\.\\%sProgram Files\\PDF_Reader\\bin\\" fullword ascii
      $s20 = "@kernel32.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule sig_0a6fd81d26b533c32ddd62d1f3d596c0 {
   meta:
      description = "dataset - file 0a6fd81d26b533c32ddd62d1f3d596c0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "6e0be1b67263c85c97f1651f3c1d480437c117f76c03957ec5ea92f52e455453"
   strings:
      $x1 = "ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f /t REG_SZ /v COM_LOADER /d \"\\\\.\\%sProgram Files\\PDF_Reader" ascii
      $x2 = "ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f /t REG_SZ /v COM_LOADER /d \"\\\\.\\%sProgram Files\\PDF_Reader" ascii
      $x3 = "c:\\windows\\system32\\syssh32.dll" fullword ascii
      $x4 = "/123456c:\\WINDOWS\\system32\\shell32.dll" fullword wide
      $x5 = "\\\\.\\%sProgram Files\\PDF_Reader\\bin\\COM7.EXE" fullword ascii
      $x6 = "C:\\RECYCLER\\bilbilal.exe" fullword ascii
      $s7 = "abletFpndZvKgnrhqndmGhhltehmphrhdbWraGJiebvmgWUhekTeiUUpxveaSVhJSbCHkbpTKZWAgHeygnOtOhkHHpqbZdaWkAnWTJinbFvhrZthvATGilbxqZdaFndg" ascii
      $s8 = "\\\\.\\%sProgram Files\\PDF_Reader\\PDF_Reader.exe" fullword ascii
      $s9 = "PDFReader.exe" fullword wide
      $s10 = "bilbilal.exe" fullword ascii
      $s11 = "com7.exe" fullword ascii
      $s12 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; ar; rv:1.9.0.5) Gecko/2008120122 Firefox/3.0.5" fullword ascii
      $s13 = "PDF Reader Launcher.exe" fullword ascii
      $s14 = "PDF_Reader FULL.exe" fullword ascii
      $s15 = "COM7.EXE" fullword ascii
      $s16 = "ashcv.exe" fullword ascii
      $s17 = "MusicMP3.exe" fullword wide
      $s18 = ".\\RECYCLER\\bilbilal.exe" fullword wide
      $s19 = "www.ibayme.eb2a.com" fullword ascii
      $s20 = "\\\\.\\%sProgram Files\\PDF_Reader\\bin\\" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      1 of ($x*) and 4 of them
}

rule sig_0a57b466934958c4ca22d236be8580f0 {
   meta:
      description = "dataset - file 0a57b466934958c4ca22d236be8580f0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "4f6b93aedae0664cac375174502f59b1f3ddb38378c34a93b8aeb4278bd031ee"
   strings:
      $s1 = " Registering DLL: '%S'." fullword ascii
      $s2 = "  WMC_CopyFile: Could not find file version for '%S'.  This file will be overwritten." fullword ascii
      $s3 = "            <requestedExecutionLevel" fullword ascii
      $s4 = "    processorArchitecture=\"x86\"" fullword ascii
      $s5 = "  WMC_CopyFile: File '%S' is newer than the version to be installed.  No copy will occur." fullword ascii
      $s6 = "  WMC_CopyFile: File '%S' is newer than the installed version.  This file will be installed." fullword ascii
      $s7 = "  WMC_CopyFile: File '%S' was only to be installed if already present on the system.  It was not present and thus will not be in" ascii
      $s8 = " Copied file '%S' to DllCache." fullword ascii
      $s9 = "  WMC_CopyFile: File '%S' is not to be installed if already present on the system.  It was present and thus will not be reinstal" ascii
      $s10 = "  WMC_CopyFile: File '%S' is not to be installed if already present on the system.  It was present and thus will not be reinstal" ascii
      $s11 = "  WMC_CopyFile: File '%S' was only to be installed if already present on the system.  It was not present and thus will not be in" ascii
      $s12 = "  Moved file '%S' to temp location for clean-up upon reboot." fullword ascii
      $s13 = "  Reboot required due to '%S' driver installation." fullword ascii
      $s14 = "  WMC_CopyFile: Could not replace file '%S'.  This file will be replaced on reboot." fullword ascii
      $s15 = "    version=\"1.0.0.0\"" fullword ascii
      $s16 = "    Dll Registration: Succeeded for file '%S'." fullword ascii
      $s17 = "  Reboot requested due to '%S' file clean-up." fullword ascii
      $s18 = "    Delayed Dll Registration: Succeeded for file '%S'." fullword ascii
      $s19 = "  Reboot requested due to '%S' file copy." fullword ascii
      $s20 = "  WMC_CopyFile: File '%S' should always to be installed.  This file will be installed." fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_0a8d2e20fd777605902fea1727ac8890 {
   meta:
      description = "dataset - file 0a8d2e20fd777605902fea1727ac8890"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "48d74ba56fcc98a4da415bf61f00adbdfb9844a40a33418bdb489d83c98ce20f"
   strings:
      $x1 = "ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f /t REG_SZ /v COM_LOADER /d \"\\\\.\\%sProgram Files\\PDF_Reader" ascii
      $x2 = "ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f /t REG_SZ /v COM_LOADER /d \"\\\\.\\%sProgram Files\\PDF_Reader" ascii
      $x3 = "c:\\windows\\system32\\syssh32.dll" fullword ascii
      $x4 = "/123456c:\\WINDOWS\\system32\\shell32.dll" fullword wide
      $x5 = "\\\\.\\%sProgram Files\\PDF_Reader\\bin\\COM7.EXE" fullword ascii
      $x6 = "C:\\RECYCLER\\bilbilal.exe" fullword ascii
      $s7 = "TyhVoeredcMgOnqCMJhgogrhSSodZpdFggqmVMitgVtTgWUsTTnCnhdTipehhtHdWZiHHklMqblVHMWipeddpWnphTfrnjmbqhjpnhMdSTeGkSrOvhdfmKJbGdhTScHh" ascii
      $s8 = "\\\\.\\%sProgram Files\\PDF_Reader\\PDF_Reader.exe" fullword ascii
      $s9 = "bilbilal.exe" fullword ascii
      $s10 = "com7.exe" fullword ascii
      $s11 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; ar; rv:1.9.0.5) Gecko/2008120122 Firefox/3.0.5" fullword ascii
      $s12 = "PDF Reader Launcher.exe" fullword ascii
      $s13 = "PDF_Reader FULL.exe" fullword ascii
      $s14 = "COM7.EXE" fullword ascii
      $s15 = "ashcv.exe" fullword ascii
      $s16 = "MusicMP3.exe" fullword wide
      $s17 = ".\\RECYCLER\\bilbilal.exe" fullword wide
      $s18 = "www.ibayme.eb2a.com" fullword ascii
      $s19 = "\\\\.\\%sProgram Files\\PDF_Reader\\bin\\" fullword ascii
      $s20 = "@kernel32.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule sig_0a40cbf48f805bdde726341d9df3e529 {
   meta:
      description = "dataset - file 0a40cbf48f805bdde726341d9df3e529"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "91bbb42b97747972f320951d3496337f93e441b6f8ee56fa9aa92be79d240add"
   strings:
      $s1 = "c:\\BuildAgent\\cm-sims2ep004\\TS2EP9_Start.tmp\\Utils\\PatchInstallerWrapper\\Release\\PatchInstallerWrapper.pdb" fullword ascii
      $s2 = "TS2UPD0.exe" fullword ascii
      $s3 = "\\TSBin\\Sims2EP8.exe" fullword ascii
      $s4 = "TS2UPD16.exe" fullword ascii
      $s5 = "\\TSBin\\Sims2.exe" fullword ascii
      $s6 = "DDDDDDf" ascii /* reversed goodware string 'fDDDDDD' */
      $s7 = "ffffffD" ascii /* reversed goodware string 'Dffffff' */
      $s8 = "fffffD" ascii /* reversed goodware string 'Dfffff' */
      $s9 = "jklmnop" fullword ascii
      $s10 = "PatchInstallerWrapper Version 1.0" fullword wide
      $s11 = "KLLMNOPQRQS" fullword ascii
      $s12 = "DFHLNWXYYWMHF" fullword ascii
      $s13 = "DHNRNNMLMMMPTNPUTLF" fullword ascii
      $s14 = "ABCDEFGHIJA" fullword ascii
      $s15 = "CDEJLCDGHGFC" fullword ascii
      $s16 = "PATCHINSTALLERWRAPPER" fullword wide
      $s17 = "Ffffffh" fullword ascii
      $s18 = "Ddwdffff" fullword ascii
      $s19 = "Ffffffj" fullword ascii
      $s20 = "Fffffffh" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule sig_0a257d858bfbdf0f03a932f094b8a9c0 {
   meta:
      description = "dataset - file 0a257d858bfbdf0f03a932f094b8a9c0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "3b48edc2092904c7016608336a2594f149434fd8f6ff8e4344c6254ca18ee977"
   strings:
      $s1 = "            <requestedExecutionLevel" fullword ascii
      $s2 = "<description>Asmertot</description>" fullword ascii
      $s3 = "    processorArchitecture=\"X86\"" fullword ascii
      $s4 = "            processorArchitecture=\"X86\"" fullword ascii
      $s5 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii
      $s6 = "            version=\"6.0.0.0\"" fullword ascii
      $s7 = "    version=\"1.0.0.0\"" fullword ascii
      $s8 = "            name=\"Microsoft.Windows.Common-Controls\"" fullword ascii
      $s9 = "LVxXa#z" fullword ascii
      $s10 = "cZtc!q" fullword ascii
      $s11 = "                level=\"asInvoker\"" fullword ascii
      $s12 = "        </requestedPrivileges>" fullword ascii
      $s13 = "LSNLR5" fullword ascii
      $s14 = "XVTqf6" fullword ascii
      $s15 = "        <requestedPrivileges>" fullword ascii
      $s16 = "bj1t[!`" fullword ascii
      $s17 = "PMh6ge" fullword ascii
      $s18 = "a~W8KEW/" fullword ascii
      $s19 = "e:P2lnr" fullword ascii
      $s20 = "b`LGx$" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule sig_0a4bf6e66f8e6b89df6f9371fbf16826 {
   meta:
      description = "dataset - file 0a4bf6e66f8e6b89df6f9371fbf16826"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "a9b81e55a8391bb0124ec50b1284fcf8dbffb34d7d66d2ac340fed1412d8d6a4"
   strings:
      $s1 = "ICMP.dll" fullword ascii
      $s2 = "Xmgclayn.exe" fullword wide
      $s3 = "4.15.8732.24636" fullword wide /* hex encoded string 'AXs"F6' */
      $s4 = "c:\\HidmaxCawQ\\srbn" fullword wide
      $s5 = "Xmgclayn" fullword wide
      $s6 = "zHvUldJXm" fullword ascii
      $s7 = "vnEshScd" fullword ascii
      $s8 = "QvyKtly" fullword ascii
      $s9 = "SunfZtat" fullword ascii
      $s10 = "Zqbar Mxnc" fullword wide
      $s11 = "Xmgclayn " fullword wide
      $s12 = " Zqbar Mxnc" fullword wide
      $s13 = "Xmgclayn Unpahxnz" fullword wide
      $s14 = " ysnxy uhvYik" fullword wide
      $s15 = "iBIRv JeBwxteId" fullword wide
      $s16 = "VfkfmrZE" fullword wide
      $s17 = "2$2p2x2" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "JzpH'u" fullword ascii
      $s19 = ":x/vJ,~" fullword ascii
      $s20 = ">?>%>?>e>?>e>?>e>?>e>?>e>?>e>?>e>?>e>?>e>?>e>?>e>?>e>?>e>?>e>?>e>?>e>?>e>?>f>?>f>?>f>?>@" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule sig_0a9f857c21c8a574702104c6d452a956 {
   meta:
      description = "dataset - file 0a9f857c21c8a574702104c6d452a956"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "0c10bbcb7460722d8d6f7feed3fe8530faaea1964f6f3a2baa9f964dcaccff39"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s2 = "status recsound c:\\\\fwfew\\qef" fullword ascii
      $s3 = "FileDescrsiption" fullword wide
      $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s5 = "MSFT Corp" fullword wide
      $s6 = "2.1.1.2" fullword wide
      $s7 = "3.1.1.3" fullword wide
      $s8 = " About" fullword wide /* Goodware String - occured 1 times */
      $s9 = "Msacm32.dll" fullword ascii /* Goodware String - occured 2 times */
      $s10 = "calc.exe" fullword wide /* Goodware String - occured 2 times */
      $s11 = "Copyright (C) 2011" fullword wide /* Goodware String - occured 2 times */
      $s12 = "      <requestedPrivileges>" fullword ascii
      $s13 = "Winmm.dll" fullword ascii /* Goodware String - occured 3 times */
      $s14 = "+&=$fh1" fullword ascii
      $s15 = "08000025" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_0a48d4d382d90d426813ca00a3b82ab0 {
   meta:
      description = "dataset - file 0a48d4d382d90d426813ca00a3b82ab0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "441b79aea9732b44b651d34d8ebeb32c43a03b1514a08305804330db487f1a4f"
   strings:
      $x1 = "C:\\Users\\MARIOA~1.BUR\\AppData\\Local\\Temp\\7zO5060.tmp\\Xerox_Scan_001_291231_931.exe" fullword wide
      $s2 = "C:\\jTqKdyh8.exe" fullword wide
      $s3 = "C:\\pH_0qYLB.exe" fullword wide
      $s4 = "C:\\CEn2qKnT.exe" fullword wide
      $s5 = "C:\\DItaaZQ5.exe" fullword wide
      $s6 = "C:\\MnVUsxFQ.exe" fullword wide
      $s7 = "C:\\eUeHCwxm.exe" fullword wide
      $s8 = "C:\\hDe6rLgz.exe" fullword wide
      $s9 = "C:\\5L8mkRaF.exe" fullword wide
      $s10 = "C:\\LvP1TLtc.exe" fullword wide
      $s11 = "C:\\cc4ZGhwm.exe" fullword wide
      $s12 = "C:\\_hS1Lbge.exe" fullword wide
      $s13 = "C:\\4RpNUrj_.exe" fullword wide
      $s14 = "C:\\vJgUKOQJ.exe" fullword wide
      $s15 = "C:\\Rl0qgFUv.exe" fullword wide
      $s16 = "C:\\EkPdQrKo.exe" fullword wide
      $s17 = "C:\\osyD6WNq.exe" fullword wide
      $s18 = "C:\\clm895Bv.exe" fullword wide
      $s19 = "C:\\WzkBzfGI.exe" fullword wide
      $s20 = "C:\\ou3Obw2F.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      1 of ($x*) and 4 of them
}

rule sig_0a7e042da428cd52b089d1a008ab74c0 {
   meta:
      description = "dataset - file 0a7e042da428cd52b089d1a008ab74c0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "628baf1438e9e34bb469bd93edc99bcf04ebde24d739afc8234a5f701ab34f8e"
   strings:
      $x1 = "C:\\Users\\User\\AppData\\Local\\Temp\\Temp1_Xerox_Scan_001_291231_931.zip\\Xerox_Scan_001_291231_931.exe" fullword wide
      $s2 = "C:\\ahygekM9.exe" fullword wide
      $s3 = "C:\\EpXdTzSv.exe" fullword wide
      $s4 = "C:\\9AIyl3__.exe" fullword wide
      $s5 = "C:\\pSlNG1pt.exe" fullword wide
      $s6 = "C:\\8OeBvngn.exe" fullword wide
      $s7 = "C:\\AVySmi2S.exe" fullword wide
      $s8 = "C:\\8rhwzfHm.exe" fullword wide
      $s9 = "C:\\lbLuVfs2.exe" fullword wide
      $s10 = "C:\\3qDdIF2k.exe" fullword wide
      $s11 = "C:\\LOMUhm8X.exe" fullword wide
      $s12 = "C:\\mlqzqvHv.exe" fullword wide
      $s13 = "C:\\eteQOaNI.exe" fullword wide
      $s14 = "C:\\0m9BvvpR.exe" fullword wide
      $s15 = "C:\\iX6aWxRt.exe" fullword wide
      $s16 = "C:\\MK2tkUva.exe" fullword wide
      $s17 = "C:\\jfzff7bC.exe" fullword wide
      $s18 = "C:\\tkrQrLge.exe" fullword wide
      $s19 = "C:\\I7aenQdh.exe" fullword wide
      $s20 = "C:\\egWNvlwj.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*) and 4 of them
}

rule sig_0a1ee148f4215282359e32342582fb20 {
   meta:
      description = "dataset - file 0a1ee148f4215282359e32342582fb20"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "b5643cea8759090c858e044e132833e8f569ca9f71d4b5f5e7fa82c7689dea7e"
   strings:
      $x1 = "C:\\Users\\User\\AppData\\Local\\Temp\\Temp1_Xerox_Scan_001_291231_931.zip\\Xerox_Scan_001_291231_931.exe" fullword wide
      $s2 = "C:\\ahygekM9.exe" fullword wide
      $s3 = "C:\\EpXdTzSv.exe" fullword wide
      $s4 = "C:\\9AIyl3__.exe" fullword wide
      $s5 = "C:\\pSlNG1pt.exe" fullword wide
      $s6 = "C:\\8OeBvngn.exe" fullword wide
      $s7 = "C:\\AVySmi2S.exe" fullword wide
      $s8 = "C:\\8rhwzfHm.exe" fullword wide
      $s9 = "C:\\lbLuVfs2.exe" fullword wide
      $s10 = "C:\\3qDdIF2k.exe" fullword wide
      $s11 = "C:\\LOMUhm8X.exe" fullword wide
      $s12 = "C:\\mlqzqvHv.exe" fullword wide
      $s13 = "C:\\eteQOaNI.exe" fullword wide
      $s14 = "C:\\0m9BvvpR.exe" fullword wide
      $s15 = "C:\\iX6aWxRt.exe" fullword wide
      $s16 = "C:\\MK2tkUva.exe" fullword wide
      $s17 = "C:\\jfzff7bC.exe" fullword wide
      $s18 = "C:\\tkrQrLge.exe" fullword wide
      $s19 = "C:\\I7aenQdh.exe" fullword wide
      $s20 = "C:\\egWNvlwj.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*) and 4 of them
}

rule sig_0a3eced8d74952c9815c44d12a040800 {
   meta:
      description = "dataset - file 0a3eced8d74952c9815c44d12a040800"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "ac44739907386b73a0f9aaa2d71db132d07f39e06c9a3deb0c522b10e803c74d"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s2 = "//ns.adobe.com/xap/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/Resour" ascii
      $s3 = "documentID=\"xmp.did:76B0E3BDAE5811E29AC1927F6C5AE63B\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>" fullword ascii
      $s4 = "32:00        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=" ascii
      $s5 = " iTXtXML:com.adobe.xmp" fullword ascii
      $s6 = "MapX.Map.5" fullword ascii
      $s7 = "f#\" xmp:CreatorTool=\"Adobe Photoshop CS5 Windows\" xmpMM:InstanceID=\"xmp.iid:76B0E3BEAE5811E29AC1927F6C5AE63B\" xmpMM:Documen" ascii
      $s8 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwpwwwwwwwwwwwwwwwtwtwwwwp" fullword ascii
      $s9 = "wwwwwtwwwwwwwwx" fullword ascii
      $s10 = "wwwwwwwwwwwwwtwtwwwwwww" fullword ascii
      $s11 = "xmp.did:76B0E3BFAE5811E29AC1927F6C5AE63B\"> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:76B0E3BCAE5811E29AC1927F6C5AE63B\" stR" ascii
      $s12 = "wwwwwtwtwwwwwwwx" fullword ascii
      $s13 = "wwwwwwwwwwwwwwwtwtwwwwp" fullword ascii
      $s14 = "wwwwwwtwwwwwwwwxp" fullword ascii
      $s15 = "wwwwtwtwwwwwwp" fullword ascii
      $s16 = "wwwtwtwwwww" fullword ascii
      $s17 = "g:\\Brb{" fullword ascii
      $s18 = "MapMark.Document" fullword wide
      $s19 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
      $s20 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule sig_0a2eb7959b9ffe62bae2c0d486f63130 {
   meta:
      description = "dataset - file 0a2eb7959b9ffe62bae2c0d486f63130"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "90050366b3ebf62face6290f5edf3005da7cfb0f9d5ccc37767de689fa5f0ef0"
   strings:
      $s1 = "C:\\Users\\c\\Desktop\\vc\\VC" fullword ascii
      $s2 = "Mp3 File(*.mp3)|*.mp3|Wma File(*.wma)|*.wma|AVI File(*.avi)|*.avi|Movie File(*.mov)|*.mov|Gdata File(*.dat)|*.mmm|Mid File(*.mid" ascii
      $s3 = ",* ,rmi)|*.mid;*.rmi|MPEG File(*.mpeg)|*.mpeg|All File(*.*)|*.*||" fullword ascii
      $s4 = "Mp3 File(*.mp3)|*.mp3|Wma File(*.wma)|*.wma|AVI File(*.avi)|*.avi|Movie File(*.mov)|*.mov|Gdata File(*.dat)|*.mmm|Mid File(*.mid" ascii
      $s5 = "http://subca.ocsp-certum.com01" fullword ascii
      $s6 = "\\Release\\" fullword ascii
      $s7 = "erein and in the repository at https://www.certum.pl/repository.0" fullword ascii
      $s8 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii
      $s9 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii
      $s10 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii
      $s11 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii
      $s12 = "si2eyE" fullword ascii
      $s13 = "\\hYpxh,<9" fullword ascii
      $s14 = "CWMPPlayer4" fullword ascii
      $s15 = "Usage of this certificate is strictly subjected to the CERTUM Certification Practice Statement (CPS) incorporated by reference h" ascii
      $s16 = ":(:D:L:X:t:|:" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "Adobe Photoshop CS4 Windows" fullword ascii
      $s18 = "iAhh(!3" fullword ascii
      $s19 = "BcsJ7'X" fullword ascii
      $s20 = "FkAsJc^" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule sig_0a9a76ccf80b64579c709c46ff30c4e0 {
   meta:
      description = "dataset - file 0a9a76ccf80b64579c709c46ff30c4e0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "84675618e6fa5e47835840eaf34fbbd5215537ceaa3a7a1e0fe6976c677f15e3"
   strings:
      $s1 = "Agent_a.exe" fullword ascii
      $s2 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s3 = "Agent_a.exeb" fullword ascii
      $s4 = "symbolc" fullword ascii
      $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s6 = ">D:\\PMS\\pms4" fullword ascii
      $s7 = "EEEEEEEEEEFC" ascii
      $s8 = "EEEEEEEEEEFD" ascii
      $s9 = "EEEEEEEEEFFB" ascii
      $s10 = "EFEEEEEEEEEB" ascii
      $s11 = "JJDJFOJOJEOJFLDJFEFJKSFDSFSG" fullword wide
      $s12 = "Expcpkb" fullword ascii
      $s13 = "xmQp0c" fullword ascii
      $s14 = "ebrary " fullword ascii
      $s15 = "Holladay" fullword wide
      $s16 = "oEbDKJt3" fullword ascii
      $s17 = "ByJWideChp7" fullword ascii
      $s18 = "23456789:;<=>?@ABCDEFGHIJKLMNOP" fullword ascii
      $s19 = "DeWFlsF" fullword ascii
      $s20 = "5mNum8(T" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule sig_0a2cfde32727ce210869593d70ce0520 {
   meta:
      description = "dataset - file 0a2cfde32727ce210869593d70ce0520"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "5bf0a53ca476bacc258368338cb8bb6f53f2f5c9af3bb42d03635eac47b3e885"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s2 = "sfdgdgdg" fullword ascii
      $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s4 = "EEEEEEEEEEFC" ascii
      $s5 = "EEEEEEEEEEFD" ascii
      $s6 = "EEEEEEEEEFFB" ascii
      $s7 = "EFEEEEEEEEEB" ascii
      $s8 = "f]`SpY" fullword ascii
      $s9 = "TVPC!pG" fullword ascii
      $s10 = "TRdU`=(" fullword ascii
      $s11 = "      <requestedPrivileges>" fullword ascii
      $s12 = "\\,5HE;" fullword ascii
      $s13 = "V^wJ!^T@" fullword ascii
      $s14 = "|,K6\"z" fullword ascii
      $s15 = "5=m`o8" fullword ascii
      $s16 = "R~bAFg" fullword ascii
      $s17 = "1}(Wbi" fullword ascii
      $s18 = "acsOJi" fullword ascii
      $s19 = ")3]|9B|" fullword ascii
      $s20 = "<Z#}:D~" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule sig_0a3a5c1e57e223f310a827c3eac192f0 {
   meta:
      description = "dataset - file 0a3a5c1e57e223f310a827c3eac192f0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "1dd513e4a69fc5b95334b719addff196140cc4386d6d9c637dfca06d399b3f91"
   strings:
      $s1 = "B*\\AF:\\Projeler\\HAKOPS Logger v11\\Server\\Project1.vbp" fullword wide
      $s2 = "FC:\\Microsoft Visual Studio\\VB98\\VBA6.dll" fullword ascii
      $s3 = "C:\\Windows\\SysWOW64\\msvbvm60.dll\\3" fullword ascii
      $s4 = "HAKOPS LOGGER v11 - [" fullword wide
      $s5 = "333333333332" ascii /* hex encoded string '333332' */
      $s6 = "http://schemas.microsoft.com/cdo/" fullword wide
      $s7 = "Hl.dll" fullword wide
      $s8 = "<!-- Identify the application security requirements: Vista and above -->" fullword ascii
      $s9 = "C:\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s10 = "o en el password " fullword wide
      $s11 = "EkranGoruntusu.jpg" fullword wide
      $s12 = "          <requestedExecutionLevel" fullword ascii
      $s13 = "configuration/smtpauthenticate" fullword wide
      $s14 = "    processorArchitecture=\"X86\"" fullword ascii
      $s15 = "                processorArchitecture=\"X86\"" fullword ascii
      $s16 = "  <description></description>" fullword ascii
      $s17 = "\\Microsoft Archives\\Logs.html" fullword wide
      $s18 = "333333333\"\"\"\"\"\"d" fullword ascii /* hex encoded string '3333=' */
      $s19 = "333333333332\"\"\"\"\"\"\"" fullword ascii /* hex encoded string '333332' */
      $s20 = "3333333#332\"\"\"\"\"\"\"" fullword ascii /* hex encoded string '33332' */
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule sig_0a9cf21a563aebe1fdd99da97f2c9400 {
   meta:
      description = "dataset - file 0a9cf21a563aebe1fdd99da97f2c9400"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "b9bf015860d23f317f2edf3803977e89175b8c8c33a0995577a81852b7c69864"
   strings:
      $s1 = "wyyke.exe" fullword wide
      $s2 = "XC:\\Windows\\system32\\Macromed\\Flash\\Flash32_12_0_0_77.oca" fullword ascii
      $s3 = "33333333444333" ascii /* hex encoded string '3333DC3' */
      $s4 = "44344444434343333333343333" ascii /* hex encoded string 'D4DDCCC333433' */
      $s5 = "bbobobbboboo" fullword ascii
      $s6 = "tuttttt" fullword ascii
      $s7 = "onakmia" fullword wide
      $s8 = "luvonjv" fullword wide
      $s9 = "g]]naocomm" fullword ascii
      $s10 = "Flash32_12_0_0_77.ocx" fullword ascii
      $s11 = "ShockwaveFlashObjectsCtl.ShockwaveFlash" fullword ascii
      $s12 = "\"%d^l'^ldZYXXX" fullword ascii
      $s13 = "KKZKZLKXL" fullword ascii
      $s14 = "ShockwaveFlash1" fullword ascii
      $s15 = "rvbcbd" fullword ascii
      $s16 = " --7@]gjmvv" fullword ascii
      $s17 = "\\]ZZXRR\\RXRRXXXXX]XYXX" fullword ascii
      $s18 = "xqxlxg" fullword ascii
      $s19 = " -QCJG" fullword ascii
      $s20 = "lmfmrq" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule sig_0a6cc767549a129fddb075c4a294fc8b {
   meta:
      description = "dataset - file 0a6cc767549a129fddb075c4a294fc8b"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "4f358e35ee4aae632d4d8af9bc66f1066ec9e450bee74a4c66ea91be9ff04942"
   strings:
      $x1 = "Downloader.exe" fullword wide
      $s2 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" pu" ascii
      $s3 = "djgpovqu" fullword ascii
      $s4 = "mgagtgvzr" fullword ascii
      $s5 = "info@andcompany.ru0" fullword ascii
      $s6 = ":$:*:4:=:C:T:\\:l:r:|:" fullword ascii
      $s7 = "+8ps3gpy006263lg+ _m " fullword ascii
      $s8 = "Downloader" fullword wide /* Goodware String - occured 11 times */
      $s9 = "3di7ucsz-ry" fullword ascii
      $s10 = "7is_4p72p2n_munzoiabk" fullword ascii
      $s11 = "awkwbxphvc#8lyv78vfda" fullword ascii
      $s12 = "Marshala Fedorenko street, 71" fullword ascii
      $s13 = "t_jiwk6x5r3tvn0" fullword ascii
      $s14 = "lCEd^[`[" fullword ascii
      $s15 = "Moscow1%0#" fullword ascii
      $s16 = "hrtsiao-0j_" fullword ascii
      $s17 = "lnrd9wb#44lj" fullword ascii
      $s18 = "f8bqfjt24" fullword ascii
      $s19 = "fqiei34d ujpf9" fullword ascii
      $s20 = "kxew+mykvqp+l9l8tqq" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule sig_0a903f4f648f71618ef330f2c0aba8ad {
   meta:
      description = "dataset - file 0a903f4f648f71618ef330f2c0aba8ad"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "9ba9cf1cdd204fbb0fcea9208d4731c4e82ee94099bffe81d1b2864ed2937275"
   strings:
      $x1 = "Downloader.exe" fullword wide
      $s2 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" pu" ascii
      $s3 = "djgpovqu" fullword ascii
      $s4 = "mgagtgvzr" fullword ascii
      $s5 = "info@andcompany.ru0" fullword ascii
      $s6 = ":$:*:4:=:C:T:\\:l:r:|:" fullword ascii
      $s7 = "+8ps3gpy006263lg+ _m " fullword ascii
      $s8 = "Downloader" fullword wide /* Goodware String - occured 11 times */
      $s9 = "3di7ucsz-ry" fullword ascii
      $s10 = "7is_4p72p2n_munzoiabk" fullword ascii
      $s11 = "awkwbxphvc#8lyv78vfda" fullword ascii
      $s12 = "Marshala Fedorenko street, 71" fullword ascii
      $s13 = "t_jiwk6x5r3tvn0" fullword ascii
      $s14 = "Moscow1%0#" fullword ascii
      $s15 = "hrtsiao-0j_" fullword ascii
      $s16 = "lnrd9wb#44lj" fullword ascii
      $s17 = "f8bqfjt24" fullword ascii
      $s18 = "fqiei34d ujpf9" fullword ascii
      $s19 = "kxew+mykvqp+l9l8tqq" fullword ascii
      $s20 = "p oh6olgp4v_w#3ho0h0w" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule sig_0a9ecb753bfda793db6d1ad4cfd4206a {
   meta:
      description = "dataset - file 0a9ecb753bfda793db6d1ad4cfd4206a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "7087a30abfb21add2453264d7f335abee6b6ed4e744f7280b1a33aa327454b44"
   strings:
      $x1 = "Downloader.exe" fullword wide
      $s2 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" pu" ascii
      $s3 = "djgpovqu" fullword ascii
      $s4 = "mgagtgvzr" fullword ascii
      $s5 = "info@andcompany.ru0" fullword ascii
      $s6 = ":$:*:4:=:C:T:\\:l:r:|:" fullword ascii
      $s7 = "+8ps3gpy006263lg+ _m " fullword ascii
      $s8 = "Downloader" fullword wide /* Goodware String - occured 11 times */
      $s9 = "3di7ucsz-ry" fullword ascii
      $s10 = "7is_4p72p2n_munzoiabk" fullword ascii
      $s11 = "awkwbxphvc#8lyv78vfda" fullword ascii
      $s12 = "Marshala Fedorenko street, 71" fullword ascii
      $s13 = "t_jiwk6x5r3tvn0" fullword ascii
      $s14 = "Moscow1%0#" fullword ascii
      $s15 = "hrtsiao-0j_" fullword ascii
      $s16 = "lnrd9wb#44lj" fullword ascii
      $s17 = "f8bqfjt24" fullword ascii
      $s18 = "fqiei34d ujpf9" fullword ascii
      $s19 = "kxew+mykvqp+l9l8tqq" fullword ascii
      $s20 = "p oh6olgp4v_w#3ho0h0w" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule sig_0a019b34b8eb080fb9f769ddcbf27f85 {
   meta:
      description = "dataset - file 0a019b34b8eb080fb9f769ddcbf27f85"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "f3acd7cc74eb379632f7929b672ea9b7479cdb1bc8d164af2e52483bf9bf6b8b"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"5.1.0.0\" processorArch" ascii
      $s2 = "schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></" ascii
      $s3 = "ependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchit" ascii
      $s4 = "UXTHEME.dll" fullword ascii
      $s5 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"5.1.0.0\" processorArch" ascii
      $s6 = "stedExecutionLevel></requestedPrivileges></security></trustInfo></assembly>" fullword ascii
      $s7 = "re=\"x86\" name=\"author.Program_Code\" type=\"win32\"></assemblyIdentity><description>Program Description</description><depende" ascii
      $s8 = "=\"x86\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\"></assemblyIdentity></dependentAssembly></dependency><trustInfo xmlns" ascii
      $s9 = "\\oMdnKiK" fullword ascii
      $s10 = "+  !39::798:)" fullword ascii
      $s11 = "LnKWBS9" fullword ascii
      $s12 = "|:|<f -" fullword ascii
      $s13 = "ccddA@B8" fullword ascii
      $s14 = "kikjQPQC" fullword ascii
      $s15 = "Wn-.Lvl" fullword ascii
      $s16 = "SRTMl$q" fullword ascii
      $s17 = "KrPkCyK" fullword ascii
      $s18 = "xbDst}y" fullword ascii
      $s19 = "TyiLmey" fullword ascii
      $s20 = "DIErMZM" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule sig_0a3b286d4f1822c54d6f071d6be1d7d0 {
   meta:
      description = "dataset - file 0a3b286d4f1822c54d6f071d6be1d7d0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "c319df0118011787cb2f871c4694ecc42c48b04e1e4fd582782bcc3b1b57d7bf"
   strings:
      $s1 = "* 4u*G38" fullword ascii
      $s2 = "JoXwBf9" fullword ascii
      $s3 = "e}_%K%" fullword ascii
      $s4 = "7qn /km" fullword ascii
      $s5 = ")D~- ;" fullword ascii
      $s6 = "U`+ 7,&k*bi" fullword ascii
      $s7 = "XMRB+ " fullword ascii
      $s8 = "K)-0E+ " fullword ascii
      $s9 = "Rich!l" fullword ascii
      $s10 = "UBga*d4" fullword ascii
      $s11 = "cMtion\\" fullword ascii
      $s12 = "C+YKqI^4wB" fullword ascii
      $s13 = "MMumlA;" fullword ascii
      $s14 = "$zlPAAt:" fullword ascii
      $s15 = "qdBQ/dB" fullword ascii
      $s16 = "BQevh0b$!v]" fullword ascii
      $s17 = "TYUe&)V" fullword ascii
      $s18 = "~HYSe=r/" fullword ascii
      $s19 = "ZZzU=_&?vd " fullword ascii
      $s20 = "wqGaxnt" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_0a3c48ef9abe7844451f92956a205430 {
   meta:
      description = "dataset - file 0a3c48ef9abe7844451f92956a205430"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "d8fcd9a9b8e664ebd4a55c074c2eca510463366e550a7eac8135f28807b14e4b"
   strings:
      $s1 = "'?<2\"E_-" fullword ascii /* hex encoded string '.' */
      $s2 = "&.Lget" fullword ascii
      $s3 = "j>)+ X" fullword ascii
      $s4 = "hOyCx65" fullword ascii
      $s5 = "_* G\\W" fullword ascii
      $s6 = "/PhgB]QW{h" fullword ascii
      $s7 = "QaDdyph" fullword ascii
      $s8 = "_RDBjT6p" fullword ascii
      $s9 = "MDgD<d&" fullword ascii
      $s10 = "cpebu?Z" fullword ascii
      $s11 = "HsEgK<J" fullword ascii
      $s12 = "DOfT11f" fullword ascii
      $s13 = "hJnSk#Qi" fullword ascii
      $s14 = "+`Vcwb5pi" fullword ascii
      $s15 = "-SnEC#xJx" fullword ascii
      $s16 = "KzwrE1C" fullword ascii
      $s17 = "+eVGdz\\z" fullword ascii
      $s18 = "OROp}hV" fullword ascii
      $s19 = "RROdzzU}" fullword ascii
      $s20 = "RpzaSPn" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_0a61b7b1f70d609f70161f4dce53d290 {
   meta:
      description = "dataset - file 0a61b7b1f70d609f70161f4dce53d290"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "b2cd7adad16447a9887db379a499bd32d0fc39d18b90c213ca3e2798ed3b7cd7"
   strings:
      $s1 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s2 = "@@@@@@u" fullword ascii /* reversed goodware string 'u@@@@@@' */
      $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s4 = ";JJJJJJJJJJJJJ~D~+JJJJ" fullword ascii
      $s5 = ";????????????????????(JJJJJJJJJJJ" fullword ascii
      $s6 = ":!:s:y:" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "pNNNNNNNN:" fullword ascii
      $s8 = "HLNN:pp" fullword ascii
      $s9 = " )&TTTR????*'" fullword ascii
      $s10 = ";JJJJJJJJJJJJJ" fullword ascii
      $s11 = "pppppppp:" fullword ascii
      $s12 = "^^^^^^^^z^^^^zzzz^^z^^^^^^^^^^" fullword ascii
      $s13 = "NNNNNNNp(" fullword ascii
      $s14 = "IIII@@\\" fullword ascii
      $s15 = ";JJJJJJJJJJJJJ/" fullword ascii
      $s16 = ":::::::::::::::::::::::::::::::::" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "D$(PSUV" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "      <requestedPrivileges>" fullword ascii
      $s19 = ":::::::::::::::::::::::::" fullword ascii /* Goodware String - occured 3 times */
      $s20 = ":::::::::::X" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule sig_0a53b5996800654a3e941929581fde80 {
   meta:
      description = "dataset - file 0a53b5996800654a3e941929581fde80"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "5eca0285dd99d86dc87b8bd37cba185dad0ef0f50ec393f7f0a91bcdbf37dc21"
   strings:
      $s1 = "C:\\Program Files\\E-yoo\\sqlite3.dll" fullword ascii
      $s2 = "1JUuo:\"" fullword ascii
      $s3 = "CLEAROVERALL" fullword wide
      $s4 = "FLVPLAYBACK" fullword wide
      $s5 = "SETVOLUME" fullword wide
      $s6 = "TBOTTOMFORM" fullword wide
      $s7 = "ms43Ba" fullword ascii
      $s8 = "^p6%cu%" fullword ascii
      $s9 = "\\BnBMaMc" fullword ascii
      $s10 = "aT -#$" fullword ascii
      $s11 = "sqlite3_step" fullword ascii /* Goodware String - occured 95 times */
      $s12 = "oHdj1YR" fullword ascii
      $s13 = "mWRf\\X" fullword ascii
      $s14 = "3Ynhs=hbK" fullword ascii
      $s15 = "=N.pDc" fullword ascii
      $s16 = "4|oNEW2}+" fullword ascii
      $s17 = "%LWPy3V3" fullword ascii
      $s18 = "I+H.IsN" fullword ascii
      $s19 = "D;lasV|J`b" fullword ascii
      $s20 = "cMGIv.&wmhv" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_0a39f5f37c63118194f191dd2e75d080 {
   meta:
      description = "dataset - file 0a39f5f37c63118194f191dd2e75d080"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "0ae82878d1efa7b8396d38a70311cd832b0cc06b23d63f400ea42fcfd6f339d6"
   strings:
      $s1 = " `7' `7' " fullword ascii /* hex encoded string 'w' */
      $s2 = "Fn5g  /g  /" fullword ascii
      $s3 = "d0?u2Get\"\\RuA" fullword ascii
      $s4 = "\" /g\"0/g\" /W\" /W\" /g\"p7g\"`7W\"`7W\"`7'\"" fullword ascii
      $s5 = "\\RWCJ\\ceeRi" fullword ascii
      $s6 = "Tbn2Fu -" fullword ascii
      $s7 = "TNRUcxC7" fullword ascii
      $s8 = "Fn0g# /g# /W#0/W# /'# /'# /" fullword ascii
      $s9 = "5g p/g `/W `/W `/g 0/g  /W  /W  /' 0/'  /" fullword ascii
      $s10 = "teoTra8" fullword ascii
      $s11 = "H.0Fg!." fullword ascii
      $s12 = "e /iZe=,5" fullword ascii
      $s13 = "% /g% /g%0/W% /W% /g% /g%p/W%`/W%`/'%`/'%" fullword ascii
      $s14 = "# 7'# 7'#p7" fullword ascii
      $s15 = "zVbrOAu3" fullword ascii
      $s16 = "ndGEed3" fullword ascii
      $s17 = " b7OJiMAksI" fullword ascii
      $s18 = "!IpGq%-7" fullword ascii
      $s19 = "SreZ@ec" fullword ascii
      $s20 = "CUVat*uil\"r" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_0a1fb314e9eee27af4cb7b8eda43ecc0 {
   meta:
      description = "dataset - file 0a1fb314e9eee27af4cb7b8eda43ecc0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "57be3e96cd66bb202030635b41691145fd7d0c9df3263fca937eb2e1ee77ac39"
   strings:
      $s1 = "sgrqMsV6" fullword ascii
      $s2 = "5'X+ %" fullword ascii
      $s3 = "shvvAg-" fullword ascii
      $s4 = "=[GrLZAJ`" fullword ascii
      $s5 = "NWbL('G" fullword ascii
      $s6 = "&vRdEA[L,'" fullword ascii
      $s7 = "lmBD\"*u" fullword ascii
      $s8 = "yCBE6}lhUv" fullword ascii
      $s9 = "(jhSe\"9E" fullword ascii
      $s10 = "_JYHS^w.@R" fullword ascii
      $s11 = "jhKfLE M{" fullword ascii
      $s12 = "eRbHH[pF" fullword ascii
      $s13 = "6EiIC^,^^K$" fullword ascii
      $s14 = "xbjUw7+x" fullword ascii
      $s15 = "QLtRN]}" fullword ascii
      $s16 = "jItXL}," fullword ascii
      $s17 = "i4Xvup?" fullword ascii
      $s18 = "tzWp7ldEV-" fullword ascii
      $s19 = "0NJcs?=2" fullword ascii
      $s20 = "8PBAtPBCuhy" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _DS_Store {
   meta:
      description = "dataset - file .DS_Store"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "f0f8485137eeb2775587d85640661f26589e72bfce1c8148049a62fe7c7ca562"
   strings:
      $s1 = "6Ilocblob" fullword ascii
      $s2 = "6dsclbool" fullword ascii
      $s3 = "are_PE" fullword wide
      $s4 = "Malware_PE Ransom_1000_2023060" fullword wide
   condition:
      uint16(0) == 0x0000 and filesize < 20KB and
      all of them
}

rule sig_0a1056d80d9b55d5b60932894189c190 {
   meta:
      description = "dataset - file 0a1056d80d9b55d5b60932894189c190"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "f9ea84daa24489e8f687fd7d1b54c5dbf1688f55cd078a4edb90bd378760ba7a"
   strings:
      $s1 = "VriN(P1V" fullword ascii
      $s2 = "Psfi,xIU/" fullword ascii
      $s3 = "E\\lNASg4E\\g" fullword ascii
      $s4 = "7zVuL=]#" fullword ascii
      $s5 = "WhPcg\"1" fullword ascii
      $s6 = "lFASg.E\\g" fullword ascii
      $s7 = "NrwCNryCNr{" fullword ascii
      $s8 = "\\9B*P;" fullword ascii
      $s9 = "\\-x$L/" fullword ascii
      $s10 = "\\9b$r-x" fullword ascii
      $s11 = "\\Wk.VW" fullword ascii
      $s12 = ">wv$\\-v" fullword ascii
      $s13 = "C 2{Pj" fullword ascii
      $s14 = "j@1@$~q" fullword ascii
      $s15 = "Tt0_`j" fullword ascii
      $s16 = "MT7b#y%b" fullword ascii
      $s17 = "!xJH?n" fullword ascii
      $s18 = "Jr/L(\\" fullword ascii
      $s19 = "E29RD&" fullword ascii
      $s20 = "JsF&~;@" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule sig_0a5f5778097bee02c3204f2d038b21a0 {
   meta:
      description = "dataset - file 0a5f5778097bee02c3204f2d038b21a0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "69f12aba25a955ab280e489bd1173231f15866d4eefdce3f29ebdf20077951f3"
   strings:
      $s1 = "meZrae6" fullword ascii
      $s2 = " /ygwQ" fullword ascii
      $s3 = "oxmb@hDm" fullword ascii
      $s4 = "E9jpeSF!" fullword ascii
      $s5 = "=jWdW4nBx" fullword ascii
      $s6 = "xlSAylQ" fullword ascii
      $s7 = "MtdM!Cy" fullword ascii
      $s8 = "6crHJ\"w4@[g" fullword ascii
      $s9 = "@xIQKh&_" fullword ascii
      $s10 = "U.zlA;" fullword ascii
      $s11 = "XiGs.mw" fullword ascii
      $s12 = "7UntiWT>&+" fullword ascii
      $s13 = "<VFVg?&" fullword ascii
      $s14 = "aRzx'XD" fullword ascii
      $s15 = "aNReCWB" fullword ascii
      $s16 = "b.Fwt$" fullword ascii
      $s17 = "bRKHPBb" fullword ascii
      $s18 = "DOXV?F#xj}" fullword ascii
      $s19 = "KXEVD\"3Y>W" fullword ascii
      $s20 = "qgXkfv+" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_0a7b2422df6ecd0a5a82e40813785426 {
   meta:
      description = "dataset - file 0a7b2422df6ecd0a5a82e40813785426"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "208337f42f1674cc946d68cfecddc55b07a36cfbbdf7f1119d6babe7d7df3f48"
   strings:
      $s1 = "'/&5''''#0&5''''\";#\"''''1.$\"" fullword ascii /* hex encoded string 'PQ' */
      $s2 = "alFreeGetTimeFormatA" fullword ascii
      $s3 = "nvkdixouevvy" fullword ascii
      $s4 = "h -}bG5." fullword ascii
      $s5 = "80^+ ]s66" fullword ascii
      $s6 = "hhwIb26" fullword ascii
      $s7 = "grPDx-/u" fullword ascii
      $s8 = "HvSSchD" fullword ascii
      $s9 = "tMOz^gMd}" fullword ascii
      $s10 = "jhoFsDR" fullword ascii
      $s11 = "r6SupEeeMsfiafvip" fullword ascii
      $s12 = "dMcPSw7[" fullword ascii
      $s13 = "hYEo|8O" fullword ascii
      $s14 = "=rawTextXl" fullword ascii
      $s15 = "GQiIHnVF" fullword ascii
      $s16 = "PLZnHJR" fullword ascii
      $s17 = "nOEp:]/#v]4H" fullword ascii
      $s18 = "h.wqB+-" fullword ascii
      $s19 = "HNqOWqNdTCwlPxOe" fullword ascii
      $s20 = "oLdFuU7FL" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule sig_0a7b8f6db3747f5c29611bf820ee9050 {
   meta:
      description = "dataset - file 0a7b8f6db3747f5c29611bf820ee9050"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "52d1ce14d628cc14745b4a1c285f8bf74438b7214110eba6e68425a3e7f39b2a"
   strings:
      $s1 = "Bu3* n" fullword ascii
      $s2 = "4FNSr4],K" fullword ascii
      $s3 = "wtbB}8X" fullword ascii
      $s4 = "LysE(cH" fullword ascii
      $s5 = "lhKdm@o" fullword ascii
      $s6 = "a5BBLS`b=" fullword ascii
      $s7 = "CEhwf8" fullword ascii
      $s8 = "Rich!4O" fullword ascii /* Goodware String - occured 4 times */
      $s9 = "Du1! n" fullword ascii
      $s10 = "n0NFe " fullword ascii
      $s11 = "*KB/Bc" fullword ascii
      $s12 = ">SQ2:L" fullword ascii
      $s13 = "H*@[8r1" fullword ascii
      $s14 = "83wq53w" fullword ascii
      $s15 = "R-|!HX" fullword ascii
      $s16 = "7y V@B" fullword ascii
      $s17 = "a5B|#I" fullword ascii
      $s18 = "o%A56N" fullword ascii
      $s19 = "f^U*9v" fullword ascii
      $s20 = "9lLy3C" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _0a4d261ac81f561af3730a8a0db4f090_0a6fd81d26b533c32ddd62d1f3d596c0_0 {
   meta:
      description = "dataset - from files 0a4d261ac81f561af3730a8a0db4f090, 0a6fd81d26b533c32ddd62d1f3d596c0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "8d2914279fed4f0ab577592a9ee71dd2547c6d68eac40c62a5d05d7cb5024d8c"
      hash2 = "6e0be1b67263c85c97f1651f3c1d480437c117f76c03957ec5ea92f52e455453"
   strings:
      $s1 = "PDFReader.exe" fullword wide
      $s2 = "kkcchckcc" fullword ascii
      $s3 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ascii
      $s4 = "ccccgcc" fullword ascii
      $s5 = "ccciccdeifgchiiic" fullword ascii
      $s6 = "cfcccgcccbbcc" fullword ascii
      $s7 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ascii
      $s8 = "gdccbxgd" fullword ascii
      $s9 = "eccbxke" fullword ascii
      $s10 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ascii
      $s11 = "bbbdcccb" ascii
      $s12 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ascii
      $s13 = "eccdccc" ascii
      $s14 = "gccccccccccccc" fullword ascii
      $s15 = "ccsccceccgcccccccgcccccccc" fullword ascii
      $s16 = "cccccccccccccccccccccccc" ascii
      $s17 = "cwdccbx" fullword ascii
      $s18 = "bbbdccc" ascii
      $s19 = "ccdefghijklmnopqr" fullword ascii
      $s20 = "ccoooooooooooodoefgoooooooooooohooooijklimn" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and pe.imphash() == "ea28f662ab831803e9a8c823439760d0" and ( 8 of them )
      ) or ( all of them )
}

rule _0a630c72ed4eaaf59b5fccadb909dc00_0a300b1bdb83fcf6913a9c6a1d372510_1 {
   meta:
      description = "dataset - from files 0a630c72ed4eaaf59b5fccadb909dc00, 0a300b1bdb83fcf6913a9c6a1d372510"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "1eb8b251e4c9d2bae4b904c15654dfa7c78693f257cb5801d74af986ef97fff0"
      hash2 = "90d4db65ee18eab573ac28862b9d258179762f9f8367797bdb8bb52c0435d128"
   strings:
      $s1 = "QQDownload.exe" fullword ascii
      $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x8" ascii
      $s3 = "TNProxy.dll" fullword wide
      $s4 = "DownloadProxy.Downloader.1" fullword wide
      $s5 = "\\tnproxy.dll" fullword wide
      $s6 = "fs_hello.qq.com" fullword ascii
      $s7 = "dlcore.dll" fullword wide
      $s8 = "Extract.dll" fullword wide
      $s9 = "ProgID = s 'DownloadProxy.Downloader.1'" fullword ascii
      $s10 = "CurVer = s 'DownloadProxy.Downloader.1'" fullword ascii
      $s11 = "VersionIndependentProgID = s 'DownloadProxy.Downloader'" fullword ascii
      $s12 = "Tencentdl.exe" fullword wide
      $s13 = "DownloadProxy.Downloader = s 'Downloader Class'" fullword ascii
      $s14 = "DownloadProxy.Downloader.1 = s 'Downloader Class'" fullword ascii
      $s15 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x8" ascii
      $s16 = "fs_report.qq.com" fullword ascii
      $s17 = "\\extract.dll" fullword wide
      $s18 = "\\dlcore.dll" fullword wide
      $s19 = ".?AV?$clone_impl@U?$error_info_injector@V?$basic_filesystem_error@V?$basic_path@V?$basic_string@_WU?$char_traits@_W@std@@V?$allo" ascii
      $s20 = "'DownloadProxy.EXE'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0a2d783ce96d3243f13012879dc2bc50_0a34e63d87175408024d8d9ed1aad320_2 {
   meta:
      description = "dataset - from files 0a2d783ce96d3243f13012879dc2bc50, 0a34e63d87175408024d8d9ed1aad320"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "501147525593dd439ffae29bdc613ceffa9e12efb0b628cf42633e8f0288323c"
      hash2 = "e0300019ea5b5c82297675868ac99a9751e7e86fd386de71762800dda9a4f41f"
   strings:
      $s1 = "1comsvcs.dll" fullword wide
      $s2 = "uiscan.exe" fullword wide
      $s3 = "0A7UcxCIG955oZgDmRDAvXtB8ATGBEiwSEh9QQXaa6KTHi8FHHsXHOjF2PeESiNmxJ6mr4iJGRy2q6ROIpXdmgpbiIm8XSNAp4AYu2XzKItWg0DXXrpPM9U6FoghnYMs" ascii
      $s4 = "fHaQSUyBJZftmIQfddJkn1Sy6YiVFTLAMx6lNGIvrFuBeBNkPtRPISPp3dKnjBc0656O40UGLvmfePhXOpoE9rhrmKL8CNXYfweYlgKYeOTkKYAu4qEdfEVGQVKtqdHi" ascii
      $s5 = "YK3UfEwNtV2bDhRJlZoCvhBk5Y7nsbIUAQqsSRNLLXnyo8jiaXsldkp5OnxnuSvSV7H1dyGpQA3gbHujeVhP0HItDPDNDRhuJpH7yMoX7LmTdvZsz0mSYzWi9LmTVUFX" ascii
      $s6 = "0A7UcxCIG955oZgDmRDAvXtB8ATGBEiwSEh9QQXaa6KTHi8FHHsXHOjF2PeESiNmxJ6mr4iJGRy2q6ROIpXdmgpbiIm8XSNAp4AYu2XzKItWg0DXXrpPM9U6FoghnYMs" ascii
      $s7 = "EiyHzWkLSyj7hTAothDmR3UBjPdkCGJDrXeobpZpNGqycI5BsLLxDKTfPUk76BJIBjqcU19QnYH0dRAVUMHqPMYOb6fEvi3Hef0Vwyj275tzXDTIizA8n3QGWWO9Rv5e" ascii
      $s8 = "rrO30g5baKYTtkKaZAuAUGRgrdw8cwJy056HNTz08USTMOrJjfL9iHUsWjUHcmMNa9tTlvwvLhyecldiqO1jMGsVuMmKVf3VcnZF4AZHcWCJdVSCKCWab7mlljHSeR9a" ascii
      $s9 = "rK0RpHnFzQIdsNK0qoceDNlEh8CdTjiuiNDX6JFyOnXI39i1LN9wbzIaTu1CvP5sKKMZYOMD7a9lRsBn407ROtFjp4vHXussh1tWS0LRGUNYABIkVJuC0mMtLz1l6tkr" ascii
      $s10 = "rrO30g5baKYTtkKaZAuAUGRgrdw8cwJy056HNTz08USTMOrJjfL9iHUsWjUHcmMNa9tTlvwvLhyecldiqO1jMGsVuMmKVf3VcnZF4AZHcWCJdVSCKCWab7mlljHSeR9a" ascii
      $s11 = "YK3UfEwNtV2bDhRJlZoCvhBk5Y7nsbIUAQqsSRNLLXnyo8jiaXsldkp5OnxnuSvSV7H1dyGpQA3gbHujeVhP0HItDPDNDRhuJpH7yMoX7LmTdvZsz0mSYzWi9LmTVUFX" ascii
      $s12 = "rSOWtwL3ntKeFLvzicg5XiNRDCYXYLulWgWggaglgGU3D2VpP1H3VWsBCBP2tZQZeRKhghEg7HYyhsJPIaVGz1CYBkyXr9LXEVtPwPL9DT9knBnGY5yP8ALPfqycBnvM" ascii
      $s13 = "xtGV0D1sU8kF8I2FSlf0lzNefmWmOHEAuJeA3etltFeeiOsSHjkS2zhaVKI7pBw8UNnGdpIAZixQChBqWoaHcNjvbVR9zgsFWZu5sFPZksViGIHGeLrGymp5X7RyW7O2" ascii
      $s14 = "EiyHzWkLSyj7hTAothDmR3UBjPdkCGJDrXeobpZpNGqycI5BsLLxDKTfPUk76BJIBjqcU19QnYH0dRAVUMHqPMYOb6fEvi3Hef0Vwyj275tzXDTIizA8n3QGWWO9Rv5e" ascii
      $s15 = "rSOWtwL3ntKeFLvzicg5XiNRDCYXYLulWgWggaglgGU3D2VpP1H3VWsBCBP2tZQZeRKhghEg7HYyhsJPIaVGz1CYBkyXr9LXEVtPwPL9DT9knBnGY5yP8ALPfqycBnvM" ascii
      $s16 = "iDLVcIrCkENFMZlMDDDHHUKf9EFw7F8Qkb2b101ZyhEEMxmsdz3839LTWDw9mKy6z1LVbAQ29ipnPrrGIgg6nUHCSlLFvwMr83" fullword ascii
      $s17 = "jjmIU8IRpShsd3UBKivTL2C3Ax0qIvlP3IihHLVTGjDNfSe7b9AK9CoYo8zMfcaL7lHizEJJbulNiq41LB7qkhunra3QoMOM66ENPL0fbs9ELubuOOFO3hwI2ec90jbX" ascii
      $s18 = "c2cXxsUplh0DNwJiFtNruntiTsuS4eCN3F9SFPB" fullword ascii
      $s19 = "0IHJyvi2c2zqIEekvlRvuing3COmITxQjXMbIFeAo5hTlGzXmpGo0m5kVABKAEbuU7dHcbvkwSW2nfXBSB0wYbc9lwC6wrT8sMcGUhw0Z4Z" fullword ascii
      $s20 = "KJBxx17n4im9agWmIbaXTdPHjgQTStmpAInQf3nqeNVdwaUkkAASUG8iIbiuFIttQj8D0jejEO6ucOQjzun7mveUlTCS8kfX6sh8sochinIbXcJapnbp4aS7g" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and pe.imphash() == "3811608d106bc5bdb881254d6131ef83" and ( 8 of them )
      ) or ( all of them )
}

rule _0a4d261ac81f561af3730a8a0db4f090_0a97c755f665666b5b54578cee795c30_0a83e60a97597440fc5c22d6a0bdf040_0a6fd81d26b533c32ddd62d1_3 {
   meta:
      description = "dataset - from files 0a4d261ac81f561af3730a8a0db4f090, 0a97c755f665666b5b54578cee795c30, 0a83e60a97597440fc5c22d6a0bdf040, 0a6fd81d26b533c32ddd62d1f3d596c0, 0a8d2e20fd777605902fea1727ac8890"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "8d2914279fed4f0ab577592a9ee71dd2547c6d68eac40c62a5d05d7cb5024d8c"
      hash2 = "5ed2cff50ad83f8269f17dafd41bda39148edc82b53c55b832862bfce1e60e50"
      hash3 = "78f0e9ae174802dc4e102d6a3430e9bd399d69038105ea1e926d3973b3b9a8de"
      hash4 = "6e0be1b67263c85c97f1651f3c1d480437c117f76c03957ec5ea92f52e455453"
      hash5 = "48d74ba56fcc98a4da415bf61f00adbdfb9844a40a33418bdb489d83c98ce20f"
   strings:
      $x1 = "ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f /t REG_SZ /v COM_LOADER /d \"\\\\.\\%sProgram Files\\PDF_Reader" ascii
      $x2 = "ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f /t REG_SZ /v COM_LOADER /d \"\\\\.\\%sProgram Files\\PDF_Reader" ascii
      $x3 = "c:\\windows\\system32\\syssh32.dll" fullword ascii
      $x4 = "/123456c:\\WINDOWS\\system32\\shell32.dll" fullword wide
      $x5 = "\\\\.\\%sProgram Files\\PDF_Reader\\bin\\COM7.EXE" fullword ascii
      $x6 = "C:\\RECYCLER\\bilbilal.exe" fullword ascii
      $s7 = "\\\\.\\%sProgram Files\\PDF_Reader\\PDF_Reader.exe" fullword ascii
      $s8 = "bilbilal.exe" fullword ascii
      $s9 = "com7.exe" fullword ascii
      $s10 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; ar; rv:1.9.0.5) Gecko/2008120122 Firefox/3.0.5" fullword ascii
      $s11 = "PDF Reader Launcher.exe" fullword ascii
      $s12 = "PDF_Reader FULL.exe" fullword ascii
      $s13 = "COM7.EXE" fullword ascii
      $s14 = "ashcv.exe" fullword ascii
      $s15 = "MusicMP3.exe" fullword wide
      $s16 = ".\\RECYCLER\\bilbilal.exe" fullword wide
      $s17 = "www.ibayme.eb2a.com" fullword ascii
      $s18 = "\\\\.\\%sProgram Files\\PDF_Reader\\bin\\" fullword ascii
      $s19 = "@kernel32.dll" fullword ascii
      $s20 = "%svmcis.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and pe.imphash() == "ea28f662ab831803e9a8c823439760d0" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _0a47d56e808fae23e2d404d78311c8f3_0a6b5d3385ed14cc6cea9343e2d64770_4 {
   meta:
      description = "dataset - from files 0a47d56e808fae23e2d404d78311c8f3, 0a6b5d3385ed14cc6cea9343e2d64770"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "ae1691d9ccf13e4f563fa3b149482358c9aba742e208adb7341a1b4f922e6572"
      hash2 = "8351d7777625045e81da81e311cf9adf467dd14ddd65638db5807911213357d0"
   strings:
      $s1 = "TFiler" fullword ascii /* Goodware String - occured 48 times */
      $s2 = "TPersistent" fullword ascii /* Goodware String - occured 55 times */
      $s3 = "Sender" fullword ascii /* Goodware String - occured 194 times */
      $s4 = "Target" fullword ascii /* Goodware String - occured 415 times */
      $s5 = "Source" fullword ascii /* Goodware String - occured 659 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _0a6cc767549a129fddb075c4a294fc8b_0a903f4f648f71618ef330f2c0aba8ad_0a9ecb753bfda793db6d1ad4cfd4206a_5 {
   meta:
      description = "dataset - from files 0a6cc767549a129fddb075c4a294fc8b, 0a903f4f648f71618ef330f2c0aba8ad, 0a9ecb753bfda793db6d1ad4cfd4206a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "4f358e35ee4aae632d4d8af9bc66f1066ec9e450bee74a4c66ea91be9ff04942"
      hash2 = "9ba9cf1cdd204fbb0fcea9208d4731c4e82ee94099bffe81d1b2864ed2937275"
      hash3 = "7087a30abfb21add2453264d7f335abee6b6ed4e744f7280b1a33aa327454b44"
   strings:
      $x1 = "Downloader.exe" fullword wide
      $s2 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" pu" ascii
      $s3 = "djgpovqu" fullword ascii
      $s4 = "mgagtgvzr" fullword ascii
      $s5 = "info@andcompany.ru0" fullword ascii
      $s6 = ":$:*:4:=:C:T:\\:l:r:|:" fullword ascii
      $s7 = "+8ps3gpy006263lg+ _m " fullword ascii
      $s8 = "Downloader" fullword wide /* Goodware String - occured 11 times */
      $s9 = "3di7ucsz-ry" fullword ascii
      $s10 = "7is_4p72p2n_munzoiabk" fullword ascii
      $s11 = "awkwbxphvc#8lyv78vfda" fullword ascii
      $s12 = "Marshala Fedorenko street, 71" fullword ascii
      $s13 = "t_jiwk6x5r3tvn0" fullword ascii
      $s14 = "Moscow1%0#" fullword ascii
      $s15 = "hrtsiao-0j_" fullword ascii
      $s16 = "lnrd9wb#44lj" fullword ascii
      $s17 = "f8bqfjt24" fullword ascii
      $s18 = "fqiei34d ujpf9" fullword ascii
      $s19 = "kxew+mykvqp+l9l8tqq" fullword ascii
      $s20 = "p oh6olgp4v_w#3ho0h0w" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "de957924b8d44dc95bdcf30aab2ebdca" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _0a630c72ed4eaaf59b5fccadb909dc00_0a70e777fb042d0b6ffecc7d2203f1f8_0a300b1bdb83fcf6913a9c6a1d372510_6 {
   meta:
      description = "dataset - from files 0a630c72ed4eaaf59b5fccadb909dc00, 0a70e777fb042d0b6ffecc7d2203f1f8, 0a300b1bdb83fcf6913a9c6a1d372510"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "1eb8b251e4c9d2bae4b904c15654dfa7c78693f257cb5801d74af986ef97fff0"
      hash2 = "978207c7983b4b6732add359a3c7a3dfb07d044d6207ce6814fe9d217ee24682"
      hash3 = "90d4db65ee18eab573ac28862b9d258179762f9f8367797bdb8bb52c0435d128"
   strings:
      $s1 = " Type Descriptor'" fullword ascii
      $s2 = " Class Hierarchy Descriptor'" fullword ascii
      $s3 = " Base Class Descriptor at (" fullword ascii
      $s4 = " Complete Object Locator'" fullword ascii
      $s5 = " delete[]" fullword ascii
      $s6 = " delete" fullword ascii
      $s7 = " new[]" fullword ascii
      $s8 = " Base Class Array'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _0a97c755f665666b5b54578cee795c30_0a83e60a97597440fc5c22d6a0bdf040_0a8d2e20fd777605902fea1727ac8890_7 {
   meta:
      description = "dataset - from files 0a97c755f665666b5b54578cee795c30, 0a83e60a97597440fc5c22d6a0bdf040, 0a8d2e20fd777605902fea1727ac8890"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "5ed2cff50ad83f8269f17dafd41bda39148edc82b53c55b832862bfce1e60e50"
      hash2 = "78f0e9ae174802dc4e102d6a3430e9bd399d69038105ea1e926d3973b3b9a8de"
      hash3 = "48d74ba56fcc98a4da415bf61f00adbdfb9844a40a33418bdb489d83c98ce20f"
   strings:
      $s1 = "68545125441256445485111.dll" fullword ascii
      $s2 = "CJlKShTHeyetiTSKddVnfWfsKSOTvSgcrdfGpUeTpHcmirhtSZSrhpnrdhAeMZhdedlWKrhddHticMrnrtnGncthFdnZdSThrJkhFSKShVdrUenOdjdpqnpadllabfWW" ascii
      $s3 = "aaaaaaaaadaaaaaaaaaaaaa" ascii
      $s4 = "aaaadaaaaaaaaaaaaaaaaaa" ascii
      $s5 = "fafkaslkjdfakdfljslfjal" fullword ascii
      $s6 = "fafkaslkjdfakdfljsalfjal" fullword ascii
      $s7 = "ddiHApemShngqmUTjAtitdSblnifAbdsSjMibeWisGiemFWeiJiTkgfWFhsjCdnslWgimGprSriFOHHdrhSSCKFxdlfWbineleentSgThJWhGHiSlKpmHfiWgTeoipyK" ascii
      $s8 = "AbeUegpsbOWhrkOqVSeielHrdjnhSFtKdWsebqcTaFlVbbnnbdnJbhWeKlWKrahHgntAddOVSMlHSdFriCHCefAigivrUnngbeyFhbidWhdadHHdeZgShrliSelehUeg" ascii
      $s9 = "erplctenlhiefAbgeFlgdxsdajegiafcHxdWaFghddGljggTnbfbdHnkiWqhdejxgZSereWMlieehrxviWniFCMdmSsMgxjrehVhdGGHnOnnHfTjycndAkkbitSJHSdl" ascii
      $s10 = "T)- .I" fullword ascii
      $s11 = "SOhrTvgSJcjhoHWmlSpoeedSMHgmednlniUjeFkbWnHgoyqqebpWlmiinhcJghomWqOrSrocivVhAicWbphxrdTTidihHSjgWtethtZFUbMvlHdldbrHSvUefverlyth" ascii
      $s12 = "LUfkpqwHMbgdijoEF{@dkhEds`dqB{APchoCRWbgrxCRelq{bnkk@k`tsqhU{LYjsyDKTijsCJOTcjx{@dkhEds`dqB{DSbqwBKRWbklsyHMTY{@dkhEds`dqB{TgrFM" ascii
      $s13 = "TyhVoeredcMgOnqCMJhgogrhSSodZpdFggqmVMitgVtTgWUsTTnCnhdTipehhtHdWZiHHklMqblVHMWipeddpWnphTfrnjmbqhjpnhMdSTeGkSrOvhdfmKJbGdhTScHh" ascii
      $s14 = "nneSapeiSZdHdrSHOrdiHefFnephStSngeilqpibdqhlgdcnCHiojUdbSMrlbdJeivKdyMthrbHpjKTsGxKHyhZnrbllxhrgHSdJpbSldsmarlbgSgMJdpdVjnpJhmmk" ascii
      $s15 = "HgntmtMHdrFHJkdglrJMlFUnHabitrxleOedhdelerTbhtbreebddgMddybhbroldGHoZxdnGWCdhihMeSSdWiKpenFFdnorfgiShWVeioslOerbnpegHJlxkacsoodT" ascii
      $s16 = "UnoTvHhFnkaerdfnlAdhSAWhOSOVtdiyHgideMedhcsSWGrSSeFfjJGdbStqGxhydnShepCfSTeoWennSesdeMinysdhsHbcHWSHqdpbbdvpmJyKllUoMSSelWrWMleS" ascii
      $s17 = "RafmrBMVafmwB{dkhEc`dQ{LebqwBKRajqEJQ{dkhEc`dQ{SXejsENcdmrx{@dkhEds`dqB{M`kQfgpuKPajotBKPU{bnkk@k`tsqhU{AfgnsyHOTgwBGN{dkhEc`dQ{" ascii
      $s18 = "hbdkCGVdlGmJAhreHbrtnbCrxekeVSiTlSxyeddxFtckpkoMrdidHKdffdMGHKWglgOFSgrFtblnHgMmUrrhdtiSdcdnbOdribyWMrgnpWAKWghMUohZsyeWvMnrehAM" ascii
      $s19 = "rSHreMHnrpapenvggKlnepKsWrbjnpjfFJlsjmhHldHnpUVbnAtykVbArpebJeeCegeqUGhavTSbeddASbdphMSntrpHndixrJyMtdkieHTcSegbhTqinOriqHdbVniS" ascii
      $s20 = "{VdstbdwDkkdgR{dsCRWhmrxINSTc{VdstbdwDkkdgR{IXkrxCLWjqAFKRa{@dkhEds`dqB{oENSdmwDINWdir{VdstbdwDkkdgR{HWfuAFOVafuINUd{dkhEc`dQ{iw" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and pe.imphash() == "ea28f662ab831803e9a8c823439760d0" and ( 8 of them )
      ) or ( all of them )
}

rule _0a97c755f665666b5b54578cee795c30_0a8d2e20fd777605902fea1727ac8890_8 {
   meta:
      description = "dataset - from files 0a97c755f665666b5b54578cee795c30, 0a8d2e20fd777605902fea1727ac8890"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "5ed2cff50ad83f8269f17dafd41bda39148edc82b53c55b832862bfce1e60e50"
      hash2 = "48d74ba56fcc98a4da415bf61f00adbdfb9844a40a33418bdb489d83c98ce20f"
   strings:
      $s1 = "ObxxdqhACerWWvCmkhbiKJmSytAAdMdSAijndllCipSbdpGehddhZtHCqolrfrgHxntSdfgnaJdMbWmrilerpningfghJHbpSnrymdnUjtVmCtsSnjSxlngnGdaciFfd" ascii
      $s2 = "hbcrdVdtrrheeCtvdMWZSGxlybnhgtSqAahyrFlJgqFdbeSebaopbryCVeyerppaAoghJKdiJOdnbibjsnaMHddveoHdjgKrZnlrMprlgVSopdZtldbWJFySnSOhlnll" ascii
      $s3 = "srqaqbxGdeeiligMbdAqnmZqtteCihWntblFOSjgxhckxddenWdndnhthcKGetsheVqgKgpSdFhdpaSTinOToqpivJSGanetZerMcbrZkGTstiHHdUfigbbOlthiSrMe" ascii
      $s4 = "rnyghdbKovgkbkpejJjGSlGddHShrjpShbeZrUAxaZMxhnhSpheyMkdUSJCbhleForiFbTbvSeHdgpvpZiikUcljpgeTbCphlGvZiAhnnMTcTFVTeecTgltHUhyFhHgF" ascii
      $s5 = "HGqAleldddyJUnlrHdfeSnfeGndskOHvdtlTiTbxtSGhryFiVkmeelebsyifeikofnjfpgidgtOddHZgiybelnlGHWqcOsCUeaGreyeppFrZrhsenadWtJVcWeppCGrr" ascii
      $s6 = "hSAqSnebOSSWdiirlOnbfbKcomgWnJdOimFtSgdiSeStnAdpFeilrWgopibSnebSvnHteGAASbtredAegSSpbdSAGWHnkUTKipntelTHxvrddlvMcGekeZGlbabhhrno" ascii
      $s7 = "rhhAhJMdhmlgobHTedndhHnbdJtUhSSodKhoiMsWeFrxfUAfrejTdsrllxjnessdnhpkjhdrsUSeSildSpddSJZdkvtidceWWedeteUdWeWCHlMtnFSOoimWbiZClHGn" ascii
      $s8 = "VSTHJfhbbWGnnkcjfxejrihbCTVVdGgegrgdboyyvMiedshdreklsrdlkebilhiixedgSiSfbphVgHMntxlbnceiMhdqqnFftlOhbWrdniZSrhHiirtmSeUMtisexpKg" ascii
      $s9 = "haeoybiOehqTmrdgGCeWeUtnjrpleHhHeqnHmynbCxdTnHbodHHOiirkTUHddZeghnfltlviWdeWKhlhtSieWVZSqtllUbFtVgbivAdieUTebcdSibSyqWdOSlgStpqi" ascii
      $s10 = "exWdbmAbStdbeedUdUShWxGhaFtKvbpaiSrlfljoriGmnbhmlfVdgpFkeWObdrarrsgdpFHZsTHMqnbOegiJxhndWTrCvcJdhtsKrGnGxqKdergGoOmtdFCxldUnAspg" ascii
      $s11 = "ddgSJkirWUrneWMqrJyriFSdasgZgdhiCsSrelbedcdirFbeMthxtsanxdmlbJVJtVdglixabkTqUChcblhfihiostoWtJaemdVikipiWWZkxddhUyspSnxdegeledlS" ascii
      $s12 = "gUSydoxnHsGrGbAMyteniKHAdWJbdStdVlvfnmpnelqgUfedhcmFWUJbbThjlopkvmGHnshhfnpovboieUlCdmdHsiFhskidOiqbVreTdMilrhhSeHGiHSArrJdxhneh" ascii
      $s13 = "bredHapvbnJnpMGUWphObiFZStihrdeeFiOhoVpJbbhibeyKolriWnSnelpUleedKWrVroVdgqhnWpemHdHqKvTbJhTShmtrqlMnMosHdKfldgtSiHdWbmSZVnJrUjiC" ascii
      $s14 = "nFeanlWneJeyOObdAZWhoyndHFalyhvmteOWySdbksVkUWriljMZpomrlhbGgdcMSfbkyWetrdtbnrUFeboVpfJdCidpfhliaKxrdniSAhWpkSdgcnigbeSogbrphHlr" ascii
      $s15 = "irbirHdiSihlbUhFrZetjliVFidtcsMbhixgTGJFSeSJeUMbelrgdryerhTMecepeVSirfSbihrMyldlettgrrZdhSdtTgrbebhaZhdSelyVepHSdHWtghMOWegngKrH" ascii
      $s16 = "djdklrJaikxiKpSnxOHviWgydbTSOvKnpHbKaSkkaxpJdAWbpWfpnvpevUepnshvGvhgkabgZsZbUlSOiHbiZeeMvievkCshxOMrHlgSipitrFhcnedqfejkdTSgdjhi" ascii
      $s17 = "pxeWSlranevSlnSmjidiWemrWSbdZCdhrSZFrUyblTAxnleglmybdeVexrVriHdckWSZdakydcxeZHthGWddlMSdnJiKdelVMGnlhCegpmhKbeGHdbhrhvdirieebGSh" ascii
      $s18 = "WlvilOSKdeSsSrxVirrKlgrqgndTOTejcllolkTtlOfxbcMvbStWbUjtUpMllCcgynrHOZpWSlhobbexHnncSdebgsSgltGWfjVWpbehdxGAHVOSJdnpMtiSAntdbsrl" ascii
      $s19 = "rlgUoMaVGeHFjGlrgbpdSWygfdsxiUdimGmSlfrnlShiViifeelngVCHTVSAHtdseknjhKenAtTrbMqlkliUkkWndqtChifilriWbnWSdonxvHeddtdpFiSSovhMHehh" ascii
      $s20 = "JthdjSWeWdjvelCneGbidpeMttrbbjrTaifdqpZpqUviMotgkneSVtdmbcoiqeWasFeZlbhtbHlgHecSrhGyObdxUhAiHFnlkitgdiGsriHdWoWdqWjdephnnnSFgceS" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and pe.imphash() == "ea28f662ab831803e9a8c823439760d0" and ( 8 of them )
      ) or ( all of them )
}

rule _0a7e042da428cd52b089d1a008ab74c0_0a1ee148f4215282359e32342582fb20_9 {
   meta:
      description = "dataset - from files 0a7e042da428cd52b089d1a008ab74c0, 0a1ee148f4215282359e32342582fb20"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "628baf1438e9e34bb469bd93edc99bcf04ebde24d739afc8234a5f701ab34f8e"
      hash2 = "b5643cea8759090c858e044e132833e8f569ca9f71d4b5f5e7fa82c7689dea7e"
   strings:
      $x1 = "C:\\Users\\User\\AppData\\Local\\Temp\\Temp1_Xerox_Scan_001_291231_931.zip\\Xerox_Scan_001_291231_931.exe" fullword wide
      $s2 = "C:\\ahygekM9.exe" fullword wide
      $s3 = "C:\\EpXdTzSv.exe" fullword wide
      $s4 = "C:\\9AIyl3__.exe" fullword wide
      $s5 = "C:\\pSlNG1pt.exe" fullword wide
      $s6 = "C:\\8OeBvngn.exe" fullword wide
      $s7 = "C:\\AVySmi2S.exe" fullword wide
      $s8 = "C:\\8rhwzfHm.exe" fullword wide
      $s9 = "C:\\lbLuVfs2.exe" fullword wide
      $s10 = "C:\\3qDdIF2k.exe" fullword wide
      $s11 = "C:\\LOMUhm8X.exe" fullword wide
      $s12 = "C:\\mlqzqvHv.exe" fullword wide
      $s13 = "C:\\eteQOaNI.exe" fullword wide
      $s14 = "C:\\0m9BvvpR.exe" fullword wide
      $s15 = "C:\\iX6aWxRt.exe" fullword wide
      $s16 = "C:\\MK2tkUva.exe" fullword wide
      $s17 = "C:\\jfzff7bC.exe" fullword wide
      $s18 = "C:\\tkrQrLge.exe" fullword wide
      $s19 = "C:\\I7aenQdh.exe" fullword wide
      $s20 = "C:\\egWNvlwj.exe" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 70KB and pe.imphash() == "24ae095bcd89ea8f038fa2dcb5699fc5" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _0a48d4d382d90d426813ca00a3b82ab0_0a7e042da428cd52b089d1a008ab74c0_0a1ee148f4215282359e32342582fb20_10 {
   meta:
      description = "dataset - from files 0a48d4d382d90d426813ca00a3b82ab0, 0a7e042da428cd52b089d1a008ab74c0, 0a1ee148f4215282359e32342582fb20"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "441b79aea9732b44b651d34d8ebeb32c43a03b1514a08305804330db487f1a4f"
      hash2 = "628baf1438e9e34bb469bd93edc99bcf04ebde24d739afc8234a5f701ab34f8e"
      hash3 = "b5643cea8759090c858e044e132833e8f569ca9f71d4b5f5e7fa82c7689dea7e"
   strings:
      $s1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s2 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security>    <requestedPrivileges>     <requestedExecutionLevel  level=\"" ascii
      $s3 = "dibelism" fullword ascii
      $s4 = "arigames" fullword ascii
      $s5 = "realefe" fullword ascii
      $s6 = "sexasion" fullword ascii
      $s7 = "sitizen" fullword wide
      $s8 = "lstatic" fullword wide
      $s9 = "Version 2.1.1" fullword wide
      $s10 = "FerDee, Version 1.5" fullword wide
      $s11 = "tell price" fullword wide
      $s12 = "cibitt" fullword ascii
      $s13 = "PQPVj h" fullword ascii
      $s14 = "secondclass" fullword ascii
      $s15 = "ssecondclass" fullword wide
      $s16 = "Juice proged" fullword wide
      $s17 = "Copyright by Sego" fullword wide
      $s18 = "About FerDee" fullword wide
      $s19 = "Copyright FerDee Inc. 2013" fullword wide
      $s20 = "nvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo></assembly>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 70KB and pe.imphash() == "24ae095bcd89ea8f038fa2dcb5699fc5" and ( 8 of them )
      ) or ( all of them )
}

rule _0a0a36bd0a7c1370bb567674fa68bfcf_0a92fc841004044f0b71a8206aa4e9f0_11 {
   meta:
      description = "dataset - from files 0a0a36bd0a7c1370bb567674fa68bfcf, 0a92fc841004044f0b71a8206aa4e9f0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "f66f73911529568cbb9041be6996575ebaf222b7a026d2e8e73bab70e91526fa"
      hash2 = "99662a5ebc3c17cf9f1b54e2053669754dca385a7c7b57c35f87f7413ae205a4"
   strings:
      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s2 = "My.Computer" fullword ascii
      $s3 = "MyTemplate" fullword ascii
      $s4 = "My.WebServices" fullword ascii
      $s5 = "Microsoft.VisualBasic" fullword ascii /* Goodware String - occured 98 times */
      $s6 = "Create__Instance__" fullword ascii
      $s7 = "Dispose__Instance__" fullword ascii
      $s8 = "My.User" fullword ascii
      $s9 = "MyProject" fullword ascii
      $s10 = "My.Application" fullword ascii
      $s11 = "MyApplication" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _0a40cbf48f805bdde726341d9df3e529_0a11e9d86df2b3382436caa79d3a15bd_12 {
   meta:
      description = "dataset - from files 0a40cbf48f805bdde726341d9df3e529, 0a11e9d86df2b3382436caa79d3a15bd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "91bbb42b97747972f320951d3496337f93e441b6f8ee56fa9aa92be79d240add"
      hash2 = "a27a93fcca805f4a8e0402577b89594d47b768bc99f760dce8e141490ba824c9"
   strings:
      $s1 = ">G\\,gu" fullword ascii
      $s2 = "}}}'zzz6sss;sss<sss<sss<sss<sss<sss<xxx<zzz<zzz<zzz<zzz<zzz<zzz<zzz<zzz<zzz<zzz<zzz<zzz<zzz<zzz<zzz<zzz<zzz<zzz<zzz<}}};}}};" fullword ascii
      $s3 = "%EiD;f" fullword ascii
      $s4 = "5BO'Zl" fullword ascii
      $s5 = "DRa-hv" fullword ascii
      $s6 = "JSf6dw" fullword ascii
      $s7 = "%1L!Je" fullword ascii
      $s8 = "(=\\2Kk" fullword ascii
      $s9 = "/;G Zj" fullword ascii
      $s10 = "3>J\"WbnA~" fullword ascii
      $s11 = ">GR%Wc}Kv" fullword ascii
      $s12 = ">JW)cs" fullword ascii
      $s13 = ".(+-skog" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _0a2150c408e22b12d329c9700448a8b0_0a2d783ce96d3243f13012879dc2bc50_0a34e63d87175408024d8d9ed1aad320_13 {
   meta:
      description = "dataset - from files 0a2150c408e22b12d329c9700448a8b0, 0a2d783ce96d3243f13012879dc2bc50, 0a34e63d87175408024d8d9ed1aad320"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-21"
      hash1 = "ef67975c209b2f7dab21da1ce2a8e7a837df4000060ade5c887e81c399d94015"
      hash2 = "501147525593dd439ffae29bdc613ceffa9e12efb0b628cf42633e8f0288323c"
      hash3 = "e0300019ea5b5c82297675868ac99a9751e7e86fd386de71762800dda9a4f41f"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s2 = "<dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" p" ascii
      $s3 = "s-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></reque" ascii
      $s4 = "orArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\"/></dependentAssembly></dependency><trustInfo xmlns=\"urn" ascii
      $s5 = "rivileges></security></trustInfo></assembly>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

