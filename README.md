# tsocks
A reverse socks5 proxy server whith port forwarding mode and forward server mode

Socks is a small program that has socks5 reverse proxy functionality, with the port forwarding agent can archieve intranet to intranet, but also has a positive socks5 proxy server.
Usage:

### 1. On the server has two network cards, one of the card is connected within a intranet, another cards connect to internet (public network ip):
```
On the target server run:
tsocks -s -p 1080
Use socks proxy server to connect to this server's public network ip and 1080 ports.
```
### 2. The target server in the intranet, our machine is also in the intranet:
```
First on the VPS run:
tsocks -f 8001 8002
ON the intranet server run:
tsocks -s -r vpsip -p 8001
In this machine socks5 proxy connection port VPS 8002
```

# tsocks
Tsocks是一个具有socks5反向代理功能的小程序，配合端口转发可以实现内网通内网的功能，同时也具有正向socks5代理服务器功能。
用法：
### 1.在具有两块网卡的服务器上，网卡一连接内网，网卡二连接外网（公网ip）：
```
在目标服务器上运行：
tsocks -s -p 1080
使用socks代理服务器连接这台服务器的公网ip和1080端口。
```
### 2.目标服务器处于内网，本机也处于内网：
```
首先在vps上面运行：
tsocks -f 8001 8002
在内网服务器上面运行：
tsocks -s -r vpsip -p 8001
在本机使用socks5代理连接vps的8002端口
```

```
usage: Tsocks [options]
	Tsocks -s -p 1028	Socks5 server mode
	Tsocks -s -r 1.1.1.1 -p 8001	Reverse socks5 server mode
	Tsocks -f 8001 8002	Port forward mode

Tsocks v1.0

optional arguments:
  -h, --help            show this help message and exit
  -s, --server          Socks5 server mode (default: False)
  -p PORT, --port PORT  Socks5 server mode listen port or remote port
                        (default: 1080)
  -r REMOTE IP, --remote REMOTE IP
                        Reverse socks5 server mode ,set remote relay IP
                        (default: None)
  -f PORT1 PORT2, --forward PORT1 PORT2
                        Set forward mode,and listen ports (default: None)
```
