# Add Roothide target handling
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
export TARGET = iphone:clang:16.5:15.0
ChoicySB_CFLAGS += -I$(THEOS)/vendor/include/roothide
else ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
TARGET = iphone:clang:16.5:15.0
else
TARGET = iphone:clang:13.7:8.0
endif

INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ChoicySB

ChoicySB_FILES = $(wildcard *.x) $(wildcard *.m) ../Shared.m ../ChoicyPrefsMigrator.m
ChoicySB_CFLAGS = -fobjc-arc -Wno-unguarded-availability-new
ChoicySB_PRIVATE_FRAMEWORKS = BackBoardServices

include $(THEOS_MAKE_PATH)/tweak.mk
