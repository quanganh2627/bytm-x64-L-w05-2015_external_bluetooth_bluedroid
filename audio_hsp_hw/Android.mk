LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	audio_hsp_hw.c

LOCAL_C_INCLUDES += . \
	$(call include-path-for, audio-utils) \

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libaudioutils \

LOCAL_MODULE := audio.hsp.default
LOCAL_MODULE_PATH := $(TARGET_OUT_SHARED_LIBRARIES)/hw

LOCAL_MODULE_TAGS := optional

include $(BUILD_SHARED_LIBRARY)
