$(call inherit-product, $(SRC_TARGET_DIR)/product/languages_full.mk)

# Inherit from the common Open Source product configuration
$(call inherit-product, $(SRC_TARGET_DIR)/product/aosp_base_telephony.mk)


LOCAL_PATH := device/raspberryPi/rpiv2

#ifeq ($(TARGET_PREBUILT_KERNEL),)
#LOCAL_KERNEL := $(LOCAL_PATH)/kernel
#else
#LOCAL_KERNEL := $(TARGET_PREBUILT_KERNEL)
#endif


# copy prebuilt kernel
#PRODUCT_COPY_FILES += \
# $(LOCAL_KERNEL):kernel

# Overrides
PRODUCT_NAME := aosp_rpiv2
PRODUCT_DEVICE := rpiv2
PRODUCT_BRAND := Android
PRODUCT_MODEL := Full AOSP on Raspberry Pi 2

PRODUCT_PACKAGES += \
    Launcher3


$(call inherit-product, device/raspberryPi/rpiv2/device.mk)