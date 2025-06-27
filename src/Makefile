CC = clang
CFLAGS = -Wall -Wextra -g

OBJS = socks5.o buffer.o selector.o stm.o parser.o main.o

proxy: $(OBJS)
	$(CC) $(CFLAGS) -o proxy $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o proxy