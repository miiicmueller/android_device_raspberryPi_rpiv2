# Release name
PRODUCT_RELEASE_NAME := cm_rpiv2

# Boot animation
TARGET_SCREEN_HEIGHT := 1920
TARGET_SCREEN_WIDTH := 1080
TARGET_BOOTANIMATION_HALF_RES := true

# Inherit some common CM stuff.
$(call inherit-product, vendor/cm/config/common_full_phone.mk)

# Inherit device configuration for p500.
$(call inherit-product, device/raspberryPi/rpiv2/full_rpiv2.mk)

PRODUCT_NAME := cm_rpiv2
PRODUCT_BRAND := google
PRODUCT_DEVICE := rpiv2
PRODUCT_MODEL := Raspberry Pi 2
PRODUCT_MANUFACTURER := Raspberry Pi

PRODUCT_BUILD_PROP_OVERRIDES += PRODUCT_NAME=rpiv2 BUILD_FINGERPRINT=raspi2/rpiv2/rpiv2:5.0.1/LRX22C/1602158:user/release-keys PRIVATE_BUILD_DESC="rpiv2-user 5.0.1 LRX22C 1602158 release-keys"

# Enable Torch
PRODUCT_PACKAGES += Torch
