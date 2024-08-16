all: pam_totp management_tool test_totp

pam_totp:
    $(MAKE) -C src

management_tool:
    $(MAKE) -C management

test_totp:
    $(MAKE) -C test

clean:
    $(MAKE) -C src clean
    $(MAKE) -C management clean
    $(MAKE) -C test clean
