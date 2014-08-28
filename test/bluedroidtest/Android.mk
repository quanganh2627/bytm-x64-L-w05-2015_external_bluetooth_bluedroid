#  Copyright (C) 2012-2013 Intel Mobile Communications GmbH
#  Copyright (C) 2009-2012 Broadcom Corporation
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at:
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_CFLAGS:= -DDYNAMIC_HCI_LOGGING

LOCAL_CFLAGS += -DBDT_LOG_ENABLE
ifdef VERIFIER
LOCAL_CFLAGS  += -DVERIFIER
LOCAL_CFLAGS  += -DBNEP_VERIFIER
LOCAL_CFLAGS  += -DAVDTP_VERIFIER
endif

ifdef TESTER
LOCAL_CFLAGS  += -DTESTER
LOCAL_CFLAGS  += -DBNEP_TESTER
LOCAL_CFLAGS  += -DAVDTP_TESTER
LOCAL_CFLAGS  += -DL2CAP_TESTER
endif

ifdef BDT_FM_TEST
LOCAL_CFLAGS  += -DBDT_BTA_FM_DEBUG
endif

LOCAL_SRC_FILES:=     \
    bluedroidtest.c \
    tcp_client.c

LOCAL_C_INCLUDES :=
LOCAL_CFLAGS := -Wno-unused-parameter

LOCAL_CFLAGS += -std=c99

LOCAL_CFLAGS += -std=c99

LOCAL_MODULE_TAGS := eng

LOCAL_MODULE:= bdt

LOCAL_SHARED_LIBRARIES += libcutils   \
                          libutils    \
                          libhardware \
                          libhardware_legacy

LOCAL_MULTILIB := 32

include $(BUILD_EXECUTABLE)
