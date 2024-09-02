# trace使用方法
## 进程跟踪
strace -e trace=process -i -f -p 进程号

## 动态内存释放跟踪
strace -e trace=process,memory -i -f -p 进程号