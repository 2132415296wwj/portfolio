# 驱动更新检测系统 - 编译脚本
# 适用环境: Linux / WSL (依赖 gcc, libsqlite3, pthread)
# 用法:
#   make        编译 server 与 client
#   make clean  删除生成的可执行文件

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -pthread
LDFLAGS = -lsqlite3 -lpthread -lcrypt

TARGETS = server client

all: $(TARGETS)

server: server.c
	$(CC) $(CFLAGS) -o server server.c $(LDFLAGS)

client: client.c
	$(CC) $(CFLAGS) -o client client.c $(LDFLAGS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean
