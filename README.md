# Install

## 0. Check the BPF and LSM environments
```shell
grep CONFIG_BPF /boot/config-5.19.0-46-generic
grep CONFIG_LSM /boot/config-5.19.0-46-generic
cp -v /boot/config-5.19.0-46-generic .config
make menuconfig
cat .config|grep CONFIG_LSM
# If there is no display ‘bpf’, please add in the CONFIG_LSM BPF configuration: CONFIG_LSM = "landlock lockdown, yama, integrity, apparmor, bpf."

# If there is not enough space on disk during compilation, do the following:
df -h
lsblk
growpart /dev/sda 3 
resize2fs /dev/sda3 
pvresize /dev/sda3
lvresize -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv
resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv
lvextend -r -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv   

# make the changes work
make
make modules_install 
make install
gedit /etc/default/grub
update-grub
# Select the kernel with the modified configuration to start
uname -mrs 
```

## 1. install go 1.20
```shell
wget https://dl.google.com/go/go1.17.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.17.linux-amd64.tar.gz
cat <<EOF >> ~/.bashrc
export PATH=$PATH:/usr/local/go/bin
EOF
source ~/.bashrc
go version

wget https://golang.google.cn/dl/go1.20.3.linux-amd64.tar.gz
tar xfz go1.20.3.linux-amd64.tar.gz -C /usr/local
cat <<EOF >> /etc/profile
export GOROOT=/usr/local/go
export GOPATH=$HOME/gowork
export GOBIN=$GOPATH/bin
export PATH=$GOPATH:$GOBIN:$GOROOT/bin:$PATH
EOF
source /etc/profile
cat <<EOF >> ~/.bashrc
source /etc/profile
EOF
go env
go env -w GOPROXY="https://goproxy.cn"
go env -w GO111MODULE=on
go version
```

## 2. install dependent libraries
```shell
go env -w GO111MODULE=on
go env -w GOPROXY=direct
go env -w GOSUMDB=off
go env -w GOPROXY=https://goproxy.cn,direct

go mod init cordon
go mod tidy
```

## 3. run
```shell
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/c/vmlinux.h
ulimit -l unlimited
make build
docker run -d -p 8080:80 --name my-nginx nginx:latest
docker exec -it my-nginx /bin/bash
./cordon --config policy/default.yaml
# docker bash exits and then re-enters
# Trigger file access: cat /etc/shadow
# go run main.go
```

## 4、Trigger the bpf audit
git clone https://github.com/kinvolk/bpf-exercises.git
cd bpf-exercises
make container
make build-exercise-04
make run-exercise-04
docker exec -it 02 /bin/bash
echo $$
go run main.go <pid>...

## 5、Trigger the capable function
docker run -d -p 8080:80 --name my-nginx nginx:latest
docker exec -it my-nginx /bin/bash
chmod 777 /etc/passwd
chown root:root /etc/passwd
mount -t tmpfs none /mnt
ifconfig eth0 down
