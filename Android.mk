LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

APP_ABI := armeabi-v7a

LOCAL_MODULE    := rd-patch
LOCAL_SRC_FILES := rd-patch.c

LOCAL_CFLAGS += -std=c11

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

APP_ABI := armeabi-v7a

LOCAL_MODULE    := rd
LOCAL_SRC_FILES := rd-patch.c

LOCAL_CFLAGS += -std=c11 -DSHARED

include $(BUILD_SHARED_LIBRARY)
