AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS = -Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBGPS_CFLAGS)
LDADD = ../common/liblayer23.a $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOCODEC_LIBS) $(LIBGPS_LIBS)

#bin_PROGRAMS = bcch_scan ccch_scan echo_test cell_log cbch_sniff
bin_PROGRAMS = scan_sdcch scan_imm_ass scan_tch

noinst_HEADERS = bcch_scan.h geo.h

bcch_scan_SOURCES = ../common/main.c app_bcch_scan.c bcch_scan.c
ccch_scan_SOURCES   = ../common/main.c app_ccch_scan.c rslms.c
echo_test_SOURCES = ../common/main.c app_echo_test.c
cell_log_LDADD = $(LDADD) -lm
cell_log_SOURCES = ../common/main.c app_cell_log.c cell_log.c geo.c
cbch_sniff_SOURCES = ../common/main.c app_cbch_sniff.c

scan_imm_ass_SOURCES = ../common/scan_imm_ass_main.c scan_imm_ass.c rslms.c
scan_imm_ass_LDADD = $(LDADD) -lpthread -lmysqlclient

scan_sdcch_SOURCES = ../common/scan_sdcch_main.c scan_sdcch.c rslms.c xcch.c gsm0503_coding.c gsm0503_conv.c gsm0503_parity.c gsm0503_mapping.c gsm0503_interleaving.c \
                    gsm0503_tables.c gsm48_rr.c
scan_sdcch_LDADD = $(LDADD) -lpthread -levent_pthreads -levent_openssl -lcrypto -lssl -levent -ljansson -lmysqlclient

scan_tch_SOURCES = ../common/scan_tch_main.c scan_tch.c rslms.c xcch.c gsm0503_coding.c gsm0503_conv.c gsm0503_parity.c gsm0503_mapping.c gsm0503_interleaving.c \
                    gsm0503_tables.c gsm48_rr.c
scan_tch_LDADD = $(LDADD) -lpthread -levent_pthreads -levent_openssl -lcrypto -lssl -levent -ljansson -lmysqlclient