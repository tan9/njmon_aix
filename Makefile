CFLAGS=-g -O3 
#CFLAGS=-g -O3 -D RAWSTATS
LDFLAGS=-lperfstat -lm 
CC=cc
GCC=gcc

VERSION=76
FILE=njmon_aix_v$(VERSION).c

# Compile on AIX 6.1 TL9 +
aix6: $(FILE)
	$(GCC) $(FILE) -o njmon_$@_v$(VERSION) $(CFLAGS) $(LDFLAGS) -D AIX6

# Compile on AIX 6.1 TL9 +
vios2: $(FILE)
	$(GCC) $(FILE) -o njmon_$@_v$(VERSION) -D VIOS -D SSP $(CFLAGS) $(LDFLAGS) -D AIX6

# Compile on AIX7.1 TL4+
aix7: $(FILE)
	$(GCC) $(FILE) -o njmon_$@_v$(VERSION) $(CFLAGS) $(LDFLAGS)

# Compile on AIX 7.2 TL4 +
vios3: $(FILE)
	$(GCC) $(FILE) -o njmon_$@_v$(VERSION) -D VIOS -D SSP $(CFLAGS) $(LDFLAGS)

# - - - - - 
clean:
	@rm -f njmon_aix*_v$(VERSION) njmon_vios*_v$(VERSION)

fix:
	chown nag:rtc njmon* nimon* Makefile

nmeasure: $(MFILE)
	$(CC) nmeasure_aix.c -o measure_aix $(CFLAGS)

tmp:
	echo cp njmon.1 ninstall njmon*$(VERSION) /tmp
	cp njmon.1 ninstall njmon*$(VERSION) /tmp

tar:
	@echo tar cvf njmon_aix_v$(VERSION).tar njmon_aix_v$(VERSION).c Makefile njmon.1 ninstall njmon_*_v$(VERSION) 
	tar cvf njmon_aix_v$(VERSION).tar njmon_aix_v$(VERSION).c Makefile njmon.1 ninstall njmon_*_v$(VERSION) 
