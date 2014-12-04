ifneq ($(BOARD_HAVE_BLUETOOTH),false)

LOCAL_PATH := $(call my-dir)

ifneq ($(CONFIG_USE_INTEL_CERT_BINARIES),true)

ifneq ($(BOARD_USES_WCS),true)

# Setup bdroid local make variables for handling configuration
ifneq ($(BOARD_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR),)
  bdroid_C_INCLUDES := $(BOARD_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR)
  bdroid_CFLAGS := -DHAS_BDROID_BUILDCFG
else
  bdroid_C_INCLUDES :=
  bdroid_CFLAGS := -DHAS_NO_BDROID_BUILDCFG
endif

include $(call all-subdir-makefiles)

# Cleanup our locals
bdroid_C_INCLUDES :=
bdroid_CFLAGS :=

endif # BOARD_USES_WCS != true

else
include $(LOCAL_PATH)/conf/Android.mk
endif # CONFIG_USE_INTEL_CERT_BINARIES

endif
