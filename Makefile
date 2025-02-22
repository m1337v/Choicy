# Add Roothide-specific configurations
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
Choicy_CFLAGS += -I$(THEOS)/vendor/include/roothide -DROOTHIDE_COMPAT=1
Choicy_LDFLAGS += -L$(THEOS)/vendor/lib/roothide -lroothide
Choicy_FILES += $(wildcard roothide/*.c)
endif

# Keep existing target configuration
ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
TARGET = iphone:clang:16.5:15.0
else ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
export TARGET = iphone:clang:16.5:15.0
else
TARGET = iphone:clang:13.7:8.0
endif

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Choicy

Choicy_FILES = Tweak.c nextstep_plist.c $(wildcard external/litehook/src/*.c)
Choicy_CFLAGS = -DTHEOS_LEAN_AND_MEAN -I./external/litehook/src -I./external/litehook/external/include

include $(THEOS_MAKE_PATH)/tweak.mk
SUBPROJECTS += ChoicyPrefs
SUBPROJECTS += ChoicySB
include $(THEOS_MAKE_PATH)/aggregate.mk

internal-stage::
	$(ECHO_NOTHING)mv "$(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/Choicy.dylib" "$(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/   Choicy.dylib" $(ECHO_END)
	$(ECHO_NOTHING)mv "$(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/Choicy.plist" "$(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/   Choicy.plist" $(ECHO_END)