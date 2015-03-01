#
# Copyright (C) 2011 The Android Open-Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# These two variables are set first, so they can be overridden
# by BoardConfigVendor.mk

include build/target/board/generic/BoardConfig.mk

TARGET_ARCH := arm
TARGET_BOARD_PLATFORM := BCM2836
TARGET_CPU_SMP := true
TARGET_CPU_ABI := armeabi-v7a
TARGET_CPU_ABI2 := armeabi
TARGET_ARCH_VARIANT := armv7-a-neon
ARCH_ARM_HAVE_TLS_REGISTER := true
TARGET_CPU_VARIANT := cortex-a7

BRCM_V3D_OPT := true
TARGET_NO_HW_VSYNC := true

# Davik variables
# Enable dex-preoptimization to speed up first boot sequence
ifeq ($(HOST_OS),linux)
  ifeq ($(TARGET_BUILD_VARIANT),user)
    ifeq ($(WITH_DEXPREOPT),)
      WITH_DEXPREOPT := true
    endif
  endif
endif
DONT_DEXPREOPT_PREBUILTS := true


# bootloader
TARGET_NO_BOOTLOADER := true
TARGET_BOOTLOADER_BOARD_NAME := rpiv2

# kernel
TARGET_KERNEL_SOURCE := kernel/raspberryPi/rpiv2
TARGET_KERNEL_CONFIG := cyanogenmod_rpiv2_defconfig
BOARD_KERNEL_IMAGE_NAME := zImage-dtb
BOARD_MKBOOTIMG_ARGS := --ramdisk_offset 0x02900000 --tags_offset 0x02700000
BOARD_KERNEL_CMDLINE := console=ttyAMA0,115200 kgdboc=ttyAMA0,115200 root=/dev/mmcblk0p2 rootfstype=ext4 rootwait
BOARD_KERNEL_BASE := 0x00000000
BOARD_KERNEL_PAGESIZE := 2048

# EGL
#BOARD_EGL_CFG := device/xiaomi/hongmi/egl.cfg


# recovery specific
#TARGET_RECOVERY_INITRC := device/xiaomi/hongmi/ramdisk/init.rc
#BOARD_CUSTOM_RECOVERY_KEYMAPPING := ../../device/xiaomi/hongmi/recovery/recovery_keys.c

TARGET_NO_RADIOIMAGE := true
TARGET_NO_RPC := true

DEVICE_RESOLUTION := 1920x1080
TARGET_SCREEN_HEIGHT := 1920
TARGET_SCREEN_WIDTH := 1080

#BOARD_HAS_NO_SELECT_BUTTON := true

# partition sizes
TARGET_USERIMAGES_USE_EXT4 := true
BOARD_BOOTIMAGE_PARTITION_SIZE := 16777216 # 16M
BOARD_RECOVERYIMAGE_PARTITION_SIZE := 671088640 #640M
BOARD_SYSTEMIMAGE_PARTITION_SIZE := 671088640 #640M
BOARD_USERDATAIMAGE_PARTITION_SIZE := 4294967296 #4g
BOARD_CACHEIMAGE_PARTITION_SIZE := 671088640 # 640M
BOARD_CACHEIMAGE_FILE_SYSTEM_TYPE := ext4
BOARD_FLASH_BLOCK_SIZE := 131072

TARGET_RELEASETOOLS_EXTENSIONS := device/raspberryPi/rpiv2

# Recovery
TARGET_RECOVERY_FSTAB = device/raspberryPi/rpiv2/recovery.fstab
RECOVERY_FSTAB_VERSION := 2
BOARD_HAS_NO_SELECT_BUTTON := true


# Enable Minikin text layout engine (will be the default soon)
USE_MINIKIN := true

# Include an expanded selection of fonts
EXTENDED_FONT_FOOTPRINT := true
