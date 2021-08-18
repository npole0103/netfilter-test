# netfilter-test
netfilter-test

---

## iptables

써드파티 툴이었다가 탑재가 되어버림.

아주 간단한 방화벽을 만들 수 있다.

리눅스 머신에서 밖으로 나가는 패킷 output

### 밖으로 나가는 모든 icmp 차단
`sudo iptables –A OUTPUT –p icmp –j DROP`

### 들어오는 모든 icmp 차단
`sudo iptables –A INPUT –p icmp –j DROP`

이 상태에서 `ping 8.8.8.8` 하면 안됨.

`sudo iptables –L` 하면 등록되어 있음

### icmp 다시 차단 해제(테이블에서 삭제)
`sudo iptables –D OUTPUT –p icmp –j DROP`

sudo iptables –L 하면 사라져 있음.

### iptables 내용 전체 삭제 (Flush)
`sudo iptables –F`

### 실습 – TCP는 다 차단하는데 80번만 허용
``` shell
sudo iptables –F
sudo iptables –A OUPUT —p tcp –j DROP
sudo iptables –A INPUT –p tcp –j DROP
sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --sport 80 –j ACCEPT
```

위는 잘못된 명령어. 룰의 순서가 잘못되었음. 제일 위에부터 순차적으로 먼저 적용되기 때문에 80번을 먼저 허용해줘여함.
``` shell
sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --sport 80 –j ACCEPT
sudo iptables –A OUPUT —p tcp –j DROP
sudo iptables –A INPUT –p tcp –j DROP
```

---

## netfilter
iptables로 못하는 세세한 옵션까지 필터링 하기 위함.

![image](https://user-images.githubusercontent.com/37138188/129920763-8a980924-421a-4f44-96c8-3f03e2aae3d9.png)

가상의 큐에다가 넣어버림.

netfilter는 드랍시킬 수 있다.

다음 명령어로 송수신되는 IP packet을 모두 netfilter queue로 넘김.
``` shell
sudo iptables -F
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -j NFQUEUE --queue-num 0
```

apt install
``` shell
# sudo apt install libmnl-dev
# sudo apt install libnfnetlink-dev
sudo apt install libnetfilter-queue-dev
```

빌드하는 법
`gcc -o nfqnl_test nfqnl_test.c -lnetfilter_queue`

---

### in-path 방식
![image](https://user-images.githubusercontent.com/37138188/129921082-d7f89a74-1636-454d-a2aa-f1f36317c8d2.png)

- 네트워크 탐지 모듈은 packet 전송 구간의 중간에 위치하게 된다.
- packet의 분석 변경 폐기 등이 가능하다.
- 장비에 이상이 있는 경우 네트워크가 끊기는 단점이 존재한다.
- 이를 위해 bypass NIC card를 사용하는 경우도 있다.
- EX : arp spoofing, netfilter

### out of path 방식 – 왔다갔다 하는 것을 복사해서 보는 기능임. 오로지 볼 수만 있음.
![image](https://user-images.githubusercontent.com/37138188/129921111-4cad1493-fb60-4301-b0e9-881877c0cb67.png)

- 네트워크 탐지 모듈은 packet 전송을 복사하여 분석을 하게 된다.
- packet의 분석만이 가능하다.
- 장비에 이상이 있어도 네트워크가 끊기지 않는 장점이 존재한다.
- 기존의 네트워크 흐름에 지장을 주지 않는다.

### in-path vs out-of-path
![image](https://user-images.githubusercontent.com/37138188/129921172-c53f97b3-a629-41e2-a00b-eb419f092a7f.png)

---
