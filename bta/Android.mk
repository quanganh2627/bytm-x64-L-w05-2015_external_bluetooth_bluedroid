ifneq ($(TARGET_SIMULATOR),true)

LOCAL_PATH:= $(call my-dir)

INC_PATH := $(LOCAL_PATH)/../../../../hardware/imc/rpc

include $(CLEAR_VARS)

ifeq ($(BOARD_HAVE_BLUETOOTH_BCM),true)
LOCAL_CFLAGS += \
    -DBOARD_HAVE_BLUETOOTH_BCM
endif
ifneq ($(BOARD_SUPPORTS_FREQUENCY_MANAGER), false)
LOCAL_CFLAGS += -DBT_FM_MITIGATION
endif
LOCAL_CFLAGS += -DBUILDCFG $(bdroid_CFLAGS)

ifdef BDT_FM_TEST
LOCAL_CFLAGS  += -DBDT_BTA_FM_DEBUG
endif

LOCAL_PRELINK_MODULE:=true
LOCAL_SRC_FILES:= \
    ./dm/bta_dm_ci.c \
    ./dm/bta_dm_act.c \
    ./dm/bta_dm_pm.c \
    ./dm/bta_dm_main.c \
    ./dm/bta_dm_cfg.c \
    ./dm/bta_dm_api.c \
    ./dm/bta_dm_sco.c \
    ./gatt/bta_gattc_api.c \
    ./gatt/bta_gatts_act.c \
    ./gatt/bta_gatts_main.c \
    ./gatt/bta_gattc_utils.c \
    ./gatt/bta_gattc_ci.c \
    ./gatt/bta_gatts_api.c \
    ./gatt/bta_gattc_main.c \
    ./gatt/bta_gattc_act.c \
    ./gatt/bta_gattc_cache.c \
    ./gatt/bta_gatts_utils.c \
    ./ag/bta_ag_sdp.c \
    ./ag/bta_ag_sco.c \
    ./ag/bta_ag_cfg.c \
    ./ag/bta_ag_main.c \
    ./ag/bta_ag_api.c \
    ./ag/bta_ag_rfc.c \
    ./ag/bta_ag_act.c \
    ./ag/bta_ag_cmd.c \
    ./ag/bta_ag_ci.c \
    ./ag/bta_ag_at.c \
    ./hh/bta_hh_cfg.c \
    ./hh/bta_hh_act.c \
    ./hh/bta_hh_api.c \
    ./hh/bta_hh_le.c \
    ./hh/bta_hh_utils.c \
    ./hh/bta_hh_main.c \
    ./pb/bta_pbs_cfg.c \
    ./fs/bta_fs_ci.c \
    ./fs/bta_fs_cfg.c \
    ./pan/bta_pan_main.c \
    ./pan/bta_pan_ci.c \
    ./pan/bta_pan_act.c \
    ./pan/bta_pan_api.c \
    ./av/bta_av_act.c \
    ./av/bta_av_ci.c \
    ./av/bta_av_api.c \
    ./av/bta_av_aact.c \
    ./av/bta_av_main.c \
    ./av/bta_av_cfg.c \
    ./av/bta_av_ssm.c \
    ./av/bta_av_sbc.c \
    ./ar/bta_ar.c \
    ./hl/bta_hl_act.c \
    ./hl/bta_hl_api.c \
    ./hl/bta_hl_main.c \
    ./hl/bta_hl_utils.c \
    ./hl/bta_hl_sdp.c \
    ./hl/bta_hl_ci.c \
    ./sys/bta_sys_main.c \
    ./sys/bta_sys_ci.c \
    ./sys/bta_sys_conn.c \
    ./sys/bta_sys_cfg.c \
    ./sys/ptim.c \
    ./sys/bd.c \
    ./sys/utl.c \
    ./jv/bta_jv_act.c \
    ./jv/bta_jv_cfg.c \
    ./jv/bta_jv_main.c \
    ./jv/bta_jv_api.c

ifneq ($(BOARD_SUPPORTS_FREQUENCY_MANAGER), false)
LOCAL_SRC_FILES+= ./fm/bta_fm.c
endif

LOCAL_C_INCLUDES+= . \
                   $(LOCAL_PATH)/include \
                   $(LOCAL_PATH)/sys \
                   $(LOCAL_PATH)/dm \
                   $(LOCAL_PATH)/hh \
                   $(LOCAL_PATH)/../gki/common \
                   $(LOCAL_PATH)/../gki/ulinux \
                   $(LOCAL_PATH)/../include \
                   $(LOCAL_PATH)/../stack/include \
                   $(LOCAL_PATH)/../stack/btm \
                   $(LOCAL_PATH)/../hcis \
                   $(LOCAL_PATH)/../hcis/patchram \
                   $(LOCAL_PATH)/../udrv/include \
                   $(LOCAL_PATH)/../brcm/include \
                   $(bdroid_C_INCLUDES) \

# uta module includes for RPC
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/core
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/cps
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/audio_ctrl
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/audio_mm
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/battery
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/gps
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/i2c
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/inet
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/lcs
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/make
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/power
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/rtc
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/sock
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/usb
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/cls/lp
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/cls/cts
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/cls
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/em
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/sys
LOCAL_C_INCLUDES += $(INC_PATH)/uta_inc/flash_plugin

# rpc module includes
LOCAL_C_INCLUDES += $(INC_PATH)/multi-client/utils/osa/android
LOCAL_C_INCLUDES += $(INC_PATH)/multi-client/utils/osa
LOCAL_C_INCLUDES += $(INC_PATH)/multi-client/utils/
LOCAL_C_INCLUDES += $(INC_PATH)/multi-client/rpc-stubs/fm/uta_rpc/uta_2_0
LOCAL_C_INCLUDES += $(INC_PATH)/multi-client/rpc-stubs/fm/uta_rpc/uta_2_0/host
LOCAL_C_INCLUDES += $(INC_PATH)/multi-client/rpc-stubs/fm/inc

LOCAL_LDLIBS := -ldl

LOCAL_WHOLE_STATIC_LIBRARIES :=
ifneq ($(BOARD_SUPPORTS_FREQUENCY_MANAGER), false)
LOCAL_WHOLE_STATIC_LIBRARIES += librpc_fmstub
endif

LOCAL_SHARED_LIBRARIES := libcutils libc libutils libdl

LOCAL_MODULE := libbt-brcm_bta
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_MODULE_TAGS := optional

include $(BUILD_STATIC_LIBRARY)

# below include is commented, because rpc-fm.mk
#is getting called by hardware/imc/fm/fmd
# build the other libraries that RPC calls depend on
#include $(INC_PATH)/multi-client/rpc-stubs/fm/rpc-fm.mk
endif  # TARGET_SIMULATOR != true