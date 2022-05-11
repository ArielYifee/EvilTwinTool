# Evil Twin - Attack and Defense Tool


<p align="center">

 ![](https://github.com/ArielYifee/EvilTwinTool/blob/main/photos/eviltwin.png) 

</p>

 

## Introduction:
This project represents an Evil Twin Attack and Defence tool. 
using python libraries such as scapy
The purpose of this project is to create a tool to perform an evil twin attack and defense.

***How the attack works?***

* **Step 1: Set up an evil twin access point.**

    we looks for a location with popular WiFi. we takes note of the Service Set Identifier (SSID) name. Then, wer uses WiFi Pineapple to set up a new account with the same SSID. Connected devices can't differentiate between legitimate connections and fake versions.
 

![](https://github.com/ArielYifee/EvilTwinTool/blob/main/photos/ap.PNG)

* **Step 2: Set up a fake captive portal.**

    Before you can sign in to most public WiFi accounts, you must fill in data on a generic login page. we will set up an exact copy of this page, hoping that they will trick the victim into offering up authentication details. Once we has those, we can log in to the network and control it.
 

* **Step 3: Encourage victims to connect to the evil twin WiFi.**

    Anyone new will  see the evil twin, and they will tap and log in. we can kick off anyone currently connected the attack, which temporarily takes the valid server offline.


## How to use our Attack
### Installing the environment:


### Lunch the Attack/Defence
```sudo python3 tool.py```

## Requirements:
##### Hardware :
* A Laptop with WIFI adapter.


##### Software Used:
* Ubuntu Linux 






