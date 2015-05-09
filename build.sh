#!sh

ndk-build NDK_PROJECT_PATH=`pwd` APP_BUILD_SCRIPT=`pwd`/Android.mk

adb push libs/armeabi/rd-patch sdcard/tmp/
adb push libs/armeabi/librd.so sdcard/tmp/

# mount -t tmpfs none /sdcard/tmp
adb shell "chmod 755 /sdcard/tmp/rd-patch"

adb shell "su -c \"sdcard/tmp/rd-patch \`pgrep <app>\`\""
