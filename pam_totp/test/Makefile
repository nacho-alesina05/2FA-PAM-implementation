CC = gcc
CFLAGS = -Wall -I../include

OBJS = management_tool.o
TARGET = management_tool

$(TARGET): $(OBJS)
    $(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

clean:
    rm -f $(OBJS) $(TARGET)
