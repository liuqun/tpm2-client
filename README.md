# For confused developers on TPM 2.0 related projects.
This tutorial shows how to use tpm2-tss(the TPM 2.0 Software Stack) and other related toolkits.

# 编译运行步骤
推荐在最新版本Fedora Linux环境下进行测试，其他几家Linux发行商(Ubuntu和Debian)的软件包仓库更新速度跟不上TPM相关工具包开发节奏。

1. Fedora下安装gcc编译器套件和TPM2 TSS，编译例子代码
```
sudo dnf install -y meson gcc g++ cmake tpm2-tss-devel

mkdir -p ../build
meson ../build
cd ../build
ninja
```

2. 在Fedora下安装最新版本软件TPM模拟器swtpm
```
sudo dnf install -y swtpm
```

3. 启动TPM 2.0模拟器，指定套接字端口号以及存储TPM状态的数据目录
```
mkdir -p /tmp/myvtpm
swtpm socket \
   --tpm2 \
   --ctrl type=tcp,port=2322 \
   --server type=tcp,port=2321 \
   --tpmstate dir=/tmp/myvtpm \
   --flags not-need-init,startup-clear
```

4. 启动main程序进行测试
```
./main
```
