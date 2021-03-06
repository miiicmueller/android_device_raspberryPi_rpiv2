ifeq ($(TARGET_PREBUILT_KERNEL),)
	LOCAL_KERNEL := device/raspberryPi/rpiv2/kernel
else
	LOCAL_KERNEL := $(TARGET_PREBUILT_KERNEL)
endif


PRODUCT_COPY_FILES += \
    device/raspberryPi/rpiv2/init.recovery.bcm2709.rc:root/init.recovery.bcm2709.rc \
    device/raspberryPi/rpiv2/fstab.bcm2709:root/fstab.bcm2709 \
    device/raspberryPi/rpiv2/recovery.fstab:root/recovery.fstab


PRODUCT_PROPERTY_OVERRIDES := \
    ro.ril.hsxpa=1 \
    ro.ril.gprsclass=10

PRODUCT_COPY_FILES := \
    brcm_usrlib/dag/vmcsx/egl.cfg:system/lib/egl/egl.cfg

PRODUCT_PACKAGES += \
    audio.primary.goldfish 


PRODUCT_PACKAGES += \
    libwpa_client \
    hostapd \
    dhcpcd.conf \
    wpa_supplicant \
    wpa_supplicant.conf


# Live Wallpapers
PRODUCT_PACKAGES += \
    LiveWallpapersPicker \
    librs_jni

PRODUCT_PACKAGES += \
    gralloc.msm8974 \
    libgenlock \
    hwcomposer.msm8974 \
    memtrack.msm8974 \
    libqdutils \
    libqdMetaData

PRODUCT_PACKAGES += \
    libc2dcolorconvert \
    libstagefrighthw \
    libOmxCore \
    libmm-omxcore \
    libOmxVdec \
    libOmxVdecHevc \
    libOmxVenc

PRODUCT_PACKAGES += \
    audio.primary.msm8974 \
    audio.a2dp.default \
    audio.usb.default \
    audio.r_submix.default \
    libaudio-resampler \
    tinymix

# Audio effects
PRODUCT_PACKAGES += \
    libqcomvisualizer \
    libqcomvoiceprocessing \
    libqcomvoiceprocessingdescriptors \
    libqcompostprocbundle

# Filesystem management tools
PRODUCT_PACKAGES += \
    e2fsck

# Enable optional sensor types
PRODUCT_PROPERTY_OVERRIDES += \
    ro.qti.sensors.smd=false \
    ro.qti.sensors.game_rv=false \
    ro.qti.sensors.georv=false \
    ro.qti.sensors.smgr_mag_cal_en=false \
    ro.qti.sensors.step_detector=false \
    ro.qti.sensors.step_counter=false

PRODUCT_PROPERTY_OVERRIDES += \
    wifi.interface=wlan0 \
    wifi.supplicant_scan_interval=15


# Audio Configuration
PRODUCT_PROPERTY_OVERRIDES += \
    persist.audio.handset.mic.type=digital \
    persist.audio.dualmic.config=endfire \
    persist.audio.fluence.voicecall=true \
    persist.audio.fluence.voicecomm=true \
    persist.audio.fluence.voicerec=false \
    persist.audio.fluence.speaker=false

# set default USB configuration
PRODUCT_DEFAULT_PROPERTY_OVERRIDES += \
    persist.sys.usb.config=mtp

# set USB OTG enabled to add support for USB storage type
PRODUCT_PROPERTY_OVERRIDES += \
    persist.sys.isUsbOtgEnabled=1

PRODUCT_CHARACTERISTICS := nosdcard

#DEVICE_PACKAGE_OVERLAYS := \
#    device/raspberryPi/rpiv2/overlay

PRODUCT_PACKAGES += libGLES_hgl


# setup dalvik vm configs.
$(call inherit-product, frameworks/native/build/phone-xhdpi-2048-dalvik-heap.mk)

