CC = gcc
CFLAGS = -Wall -I../include

OBJS = base32.o qr_code.o totp.o main.o pam_module.o
TARGET = pam_totp

$(TARGET): $(OBJS)
    $(CC) $(CFLAGS) -o $(TARGET) $(OBJS) -lqrencode -lpam

clean:
    rm -f $(OBJS) $(TARGET)
