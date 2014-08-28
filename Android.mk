 #######################################################################
 #  Copyright (C) 2012-2013 Intel Mobile Communications GmbH
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
 #######################################################################

LOCAL_PATH := $(call my-dir)

bdroid_CFLAGS := -Wno-unused-parameter

# Setup bdroid local make variables for handling configuration
ifneq ($(BOARD_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR),)
  bdroid_C_INCLUDES := $(BOARD_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR)
  bdroid_CFLAGS += -DHAS_BDROID_BUILDCFG
else
  bdroid_C_INCLUDES :=
  bdroid_CFLAGS += -DHAS_NO_BDROID_BUILDCFG
endif
ifdef VERIFIER
bdroid_CFLAGS  += -DVERIFIER
bdroid_CFLAGS  += -DBNEP_VERIFIER
bdroid_CFLAGS  += -DAVDTP_VERIFIER
endif

ifdef TESTER
bdroid_CFLAGS  += -DTESTER
bdroid_CFLAGS  += -DBNEP_TESTER
bdroid_CFLAGS  += -DAVDTP_TESTER
bdroid_CFLAGS  += -DL2CAP_TESTER
endif

bdroid_CFLAGS += -Wall -Werror

ifneq ($(BOARD_BLUETOOTH_BDROID_HCILP_INCLUDED),)
  bdroid_CFLAGS += -DHCILP_INCLUDED=$(BOARD_BLUETOOTH_BDROID_HCILP_INCLUDED)
endif

include $(call all-subdir-makefiles)

# Cleanup our locals
bdroid_C_INCLUDES :=
bdroid_CFLAGS :=
