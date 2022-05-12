# Evil Twin - Attack and Defense Tool


<p align="center">

 ![](https://github.com/ArielYifee/EvilTwinTool/blob/main/photos/eviltwin.png) 

</p>

 

## Introduction:
This project represents an Evil Twin Attack and Defence tool. 
using python libraries such as scapy
The purpose of this project is to create a tool to perform an evil twin attack and defense.

***How the attack works?***

* **Step 1: Choosing an interface to put in 'monitor mode'**

  Here you need to choose the network interface that will scan the network for possible APs (Access Points) to attack, and after that will send the de-authentication packets
Notice that you need to choose the network interface that can be switched to 'monitor mode'

 

* **Step 2: Scanning the network for AP to attack**

  Here you will see all the APs that were found in the network scan, and you need to choose the AP you want to attack. If no AP was found, you can choose either to rescan the network or to quit

 

* **Step 3: Verifying that at least 1 client connected to the AP you choose**

  In order to attack the chosen AP we need to verify that there is at least 1 client connected to it. If no client found, you can choose either to rescan for clients or to quit


* **Step 4: Disconnect the connection between the AP from the client**

  Here we want to disconnect between the chosen AP and client. We will do that by running deauth.py, this file will run in the background as long as the attack is running


* **Step 5: Choosing an interface that will be used for the fake AP**

  Here you need to choose the network interface that will be used as the fake AP
Notice that this network interface needs to be in 'managed mode', and that you cannot choose the same network interface as you choose at the beginning (it is still sending the deauthentication packets in the background)


* **Step 6: Activation of the fake AP**

  Here we will start running the fake AP. First, we will create the configuration files using create_conf_files.py. Second, we activate the fake AP
After the fake AP will start running, the attacked client will be able to connect to it. After the client conected
Notice that the IP of the fake AP will be - 10.0.0.1 When the fake AP start running a new terminal, that will run index2.js, will be opened in order to run the web server


***How the defense works?***

* **Step 1: Choosing an interface to put in 'monitor mode'**

  Here you need to choose the network interface that will scan the network for possible APs (Access Points) to defense, and after that will send the de-authentication packets
Notice that you need to choose the network interface that can be switched to 'monitor mode'


* **Step 2: Scanning the network for AP to attack**

  Here you will see all the APs that were found in the network scan, and you need to choose the AP you want to defense. If no AP was found, you can choose either to rescan the network or to quit


* **Step 3: Sniffing the packets and checking for attack.**


* **Step 4: Search for malicious AP**


* **Step 5: Start deauthentication attack**




## How to use our Attack
### Installing the environment:
```chmod +x requirements.sh``` 

```./requirements.sh```


### Lunch the Attack/Defence
```sudo python3 Tool.py```

## Requirements:
##### Hardware :
* Linux operating system, with two network interfaces,so that both can enter monitor mode.
* Python 3.9 and above


##### Software Used:
* Ubuntu Linux 






