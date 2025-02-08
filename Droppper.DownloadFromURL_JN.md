![](media/7ff1d5be37fa548c8e572cb0d60f5783.png)

Practical Malware Analysis & Triage

Malware Analysis Report

Droppper.DownloadFromURL Malware

FEB 2025 \| Athiwat Tiprasaharn \| Jitlada-Naomi Cybersecurity Inc. \| v1.0

Table of Contents

[Executive Summary](#executive-summary)

[High-Level Technical Summary](#high-level-technical-summary)

[Malware Compositions](#malware-compositions)

[Basic Static Analysis](#basic-static-analysis)

[Basic Dynamic Analysis](#basic-dynamic-analysis)

[Advanced Static Analysis](#advanced-static-analysis)

[Advanced Dynamic Analysis](#advanced-dynamic-analysis)

[Indicators of Compromise](#indicators-of-compromise)

[Network-based Indicators](#network-based-indicators)

[Host-based Indicators](#host-based-indicators)

[Rules and Signature](#rules-and-signature)

[Appendices](#appendices)

[A. YARA Rule](#a-yara-rule)

[B. Callback URL](#b-callback-url)

# 

# Executive Summary

| SHA 256 | 92730427321a1c4ccfc0d0580834daef98121efa9bb8963da332bfd6cf1fda8a |
|---------|------------------------------------------------------------------|

Droppper.DownloadFromURL is a dropper malware which first identified in Oct 8th, 2021. It is an executable file runs on the x86-Arch Windows system.

Network analysis revealed outbound connections to a remote URL. System artifacts include intermittent black screen pop-ups and a newly created executable ('CR433101.dat.exe') located in 'C:\\Users\\Public\\Documents'.

Attached are the Yara rules developed for identifying this malware. The sample and its corresponding hash have been submitted to VirusTotal for community analysis.

# High-Level Technical Summary

![](media/debd43f4d50f26023bc725a4743fbac0.png)

Figure 1 Malware process summary chart

“Droppper.DownloadFromURL.exe” has two stages; First, download the malware component (“favicon.ico” but saved as “CR433101.dat.exe”) from “ssl-6582datamanager.helpdeskbros.local”. Second, if malware component had been downloaded completely, it contacted to callback URL “http://huskyhacks.dev”.

# Malware Compositions

| File name                    | SHA256                                                           |
|------------------------------|------------------------------------------------------------------|
| Droppper.DownloadFromURL.exe | 92730427321a1c4ccfc0d0580834daef98121efa9bb8963da332bfd6cf1fda8a |
| CR433101.dat.exe             | c090fad79bc646b4c8573cb3b49228b96c5b7c93a50f0e3b2be9839ed8b2dd8b |

After finishing to run “Droppper.DownloadFromURL.exe” malware, it continued to make HTTP GET Request to download the initial file “favicon.ico”, however, the file was saved as “CR433101.dat.exe”

If it had succeeded to download and save the file, the malware stepped to contact with callback URL (which is in Appendices B). If it had failed, the malware ended its operation and deleted itself.

# Basic Static Analysis

![](media/744f4f1005777c7099faf90275816006.png)

Figure 2 File Hash from Cutter

![](media/9f4187548dfa98f3ace83b8c6292e708.png)

Figure 3 Imports from PEStudio

![](media/a1f7856df629c5f41f019e7b60f4730f.png)

Figure 4 Libraries from PEStudio

![](media/ab5dac9f4d0205796422017dcbf4f450.png)

Figure 5 Strings from Floss

# Basic Dynamic Analysis

![](media/63235d1c0b5d2128af6788d06f8889cd.png)

Figure 6 Found a command to save a file on C:\\Users\\Public\\Documents\\ via Procmoc

![](media/7122943300127729b4069131e13cd7f2.png)

Figure 7 Malware lets the victim ask for IP address of ssl-6582datamanager.helpdeskbros.local (captured from wireshark)

![](media/a9523543db0b61ec25460288cb58b2b7.png)

Figure 8 Send HTTP Get Request for favicon.ico

![](media/a13bb3c3e2cedeeeaadee17bbb36ca54.png)

Figure 9 Also ask for ip address of huskyhacks.dev

![](media/1cf1446acdee2b045001f5a497768103.png)

Figure 10 Send HTTP Get Request to <http://huskyhacks.dev>

![](media/485ada6052662f2dd862c24c6fa6c464.png)

Figure 11 Found the response after previous request, which INetSim acted as a huskyhacks.dev server

![](media/6c55f3ccdf59d3db0b2fbb5e54f1d525.png)

Figure 12 Found the downloaded file after run malware

# Advanced Static Analysis

![](media/f5a13fd64cc0fdf69c938170c0d49c7f.png)

Figure 13 main function

It called "URLDownloadToFileW" API to download file. Then test the value in eax, if file had been completely downloaded, eax = 0 and run the next operation. However, if eax was not equal 0, it jumped to 0x401142

![](media/a3e4e90b49b1e0b5efd5306912fa0815.png)

Figure 14 Completely download file

If the malware completely downloaded file, it continued to contact with <http://huskyhacks.dev>

![](media/386503245fb27d3e3587539d8f5c7fe2.png)

Figure 15 Failed to download

If the malware cannot download the file, it jumped to 0x00401142. After that it ran the process to delete its activities and close the operation.

# Advanced Dynamic Analysis

![](media/8422d3d6c42c8e47033e1cc94cce99c8.png)

Figure 16 x32dgb set ZF = 1

![](media/1f704e68bca150fe8e6bc1b0980b9867.png)

Figure 17 Malware can contact huskyhacks.dev

If ZF = 1, the malware continued to the next process to contact <http://huskyhacks.dev>

![](media/9e8f4673c0fb5dca10f8f8aee26caaf2.png)

Figure 18 x32dgb set ZF = 0

![](media/f9d6cb2916b767dc03b62800ce122885.png)

Figure 19 Malware jump to 0x00401142 process

If ZF = 0, the malware jumped to the process which continued to delete itself

# Indicators of Compromise

## Network-based Indicators

![](media/52495cd72a75c4fe281aa9a221b18886.png)

Figure 20 This should be the initial step to download malware components

ssl-6582datamanager.helpdeskbros.local should be the site which contains malware component to do the next operation

## Host-based Indicators

![](media/022c6bd37721660e7967df98e2b349e5.png)

Figure 21 The downloaded file on the victim

From cutter, the malware downloaded the file favicon.ico, but saved the file as the name CR433101.dat.exe in path C:\\Users\\Public\\Documents

![](media/f4d887ed3551759d073251e91d6c2fe0.png)

Figure 22 Download file

# Rules and Signature

A full set of YARA rules is included in Appendix A.

# Appendices

## A. YARA Rule

![](media/adbf708cb34394deff6d1655812f267c.png)

Figure 23 Yara Rule

## B. Callback URL

| Domain                                        | Port |
|-----------------------------------------------|------|
| http://ssl-6582datamanager.helpdeskbros.local | 80   |
| http://husky.hacks.dev                        | 80   |
