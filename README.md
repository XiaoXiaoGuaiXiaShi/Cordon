# Install

## 0. 检查BPF、LSM环境
```shell
grep CONFIG_BPF /boot/config-5.19.0-46-generic
grep CONFIG_LSM /boot/config-5.19.0-46-generic
# 当前内核CONFIG_LSM配置中无bpf，需重新编译，内核源码在/usr/src
cp -v /boot/config-5.19.0-46-generic .config
make menuconfig
cat .config|grep CONFIG_LSM
# 在CONFIG_LSM中添加bpf配置：CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor,bpf"

# 若编译期间磁盘空间不够
df -h #查看磁盘空间使用情况
lsblk #查看块设备信息
growpart /dev/sda 3 #扩容sda下第3块磁盘
resize2fs /dev/sda3 #将磁盘挂载sda3
# 将物理体积 (pv) 增加到最大大小
pvresize /dev/sda3
# 将逻辑卷 (LV) 扩展到最大大小以匹配
lvresize -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv
# 扩展文件系统本身
resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv
lvextend -r -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv   #按百分比扩容

make
make modules_install 
make install
gedit /etc/default/grub
# 注释grub_hidden配置。把grub_timeout_style=hidden给删除或者注释掉，把grub_cmdline_linux_default修改为text。
# 使修改生效
update-grub
# 设置成功后重启
# 进入advanced选择对应的内核版本(5.19.0)启动
uname -mrs 

# 或者可以通过在引导加载程序配置中添加内核的命令行参数来CONFIG_LSM启用bpf
# vim /boot/config-5.19.0-46-generic
# 重启后查看
# 同时修改/etc/default/grub中GRUB_CMDLINE_LINUX_DEFAULT="lsm=bpf,capability"

# 解决Ubuntu历史版本更换镜像源的问题：https://blog.csdn.net/weixin_45450338/article/details/134677240
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
# 解压文件
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
# 1.go设置代理
go env -w GO111MODULE=on
go env -w GOPROXY=direct
go env -w GOSUMDB=off
go env -w GOPROXY=https://goproxy.cn,direct

# 2.安装依赖库
go mod init cordon
go mod tidy
# 或者如下：
go get github.com/urfave/cli/v2@v2.3.0  #实现命令行参数的解析
go get gopkg.in/yaml.v2@v2.4.0  #将YAML数据格式编码和解码为Go语言数据结构
go get github.com/sirupsen/logrus@v1.8.1  #结构化日志库


```

## 3. run
```shell
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/c/vmlinux.h
ulimit -l unlimited
make build
docker run -d -p 8080:80 --name my-nginx nginx:latest
docker exec -it my-nginx /bin/bash
./cordon --config policy/default.yaml
# docker bash exit后重新进入
# 触发文件访问：cat /etc/shadow
# go run main.go
```

## 4、触发bpf审计
git clone https://github.com/kinvolk/bpf-exercises.git
cd bpf-exercises
make container
make build-exercise-04
make run-exercise-04
docker exec -it 02 /bin/bash
echo $$
go run main.go <pid>...

## 5、触发capable函数
docker run -d -p 8080:80 --name my-nginx nginx:latest
docker exec -it my-nginx /bin/bash
chmod 777 /etc/passwd
chown root:root /etc/passwd
mount -t tmpfs none /mnt
ifconfig eth0 down

