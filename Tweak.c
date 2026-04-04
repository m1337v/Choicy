// Copyright (c) 2019-2021 Lars Fröder

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <mach/mach.h>
#include <stdlib.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach/task_info.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <xpc/xpc.h>
#include <libgen.h>
#include <os/log.h>
#include <os/lock.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <roothide.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <ptrauth.h>
#include <litehook.h>
#include "dyld_interpose.h"
#include "nextstep_plist.h"
#include "fishhook.h"

void *(*dlopen_orig)(const char*, int);
void *dlopen_hook(const char *path, int mode);

void *(*dyld_dlopen_orig)(const void *, const char*, int);
void *dyld_dlopen_hook(const void *dyld, const char *path, int mode);

bool gShouldLog = false;
#define os_log_dbg(args ...) if (gShouldLog) os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_DEBUG, args)
#define os_log_err(args ...) if (gShouldLog) os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_ERROR, args)

extern xpc_object_t xpc_create_from_plist(const void *buf, size_t len);
#define kEnvDeniedTweaksOverride "CHOICY_DENIED_TWEAKS_OVERRIDE"
#define kEnvAllowedTweaksOverride "CHOICY_ALLOWED_TWEAKS_OVERRIDE"
#define kEnvOverwriteGlobalConfigurationOverride "CHOICY_OVERWRITE_GLOBAL_TWEAK_CONFIGURATION_OVERRIDE"
#define kChoicyPrefsPlistPath jbroot("/var/mobile/Library/Preferences/com.opa334.choicyprefs.plist")
#define kChoicyPrefsKeyGlobalDeniedTweaks "globalDeniedTweaks"
#define kChoicyPrefsKeyAppSettings "appSettings"
#define kChoicyPrefsKeyDaemonSettings "daemonSettings"
#define kChoicyProcessPrefsKeyTweakInjectionDisabled "tweakInjectionDisabled"
#define kChoicyProcessPrefsKeyCustomTweakConfigurationEnabled "customTweakConfigurationEnabled"
#define kChoicyProcessPrefsKeyAllowDenyMode "allowDenyMode"
#define kChoicyProcessPrefsKeyDeniedTweaks "deniedTweaks"
#define kChoicyProcessPrefsKeyAllowedTweaks "allowedTweaks"
#define kChoicyProcessPrefsKeyOverwriteGlobalTweakConfiguration "overwriteGlobalTweakConfiguration"
#define kChoicyProcessPrefsKeyAggressiveHideJBRootImages "aggressiveHideJBRootImages"
#define kPreferencesBundleID "com.apple.Preferences"
#define kSpringboardBundleID "com.apple.springboard"

enum {
	PROCESS_TYPE_BINARY,
	PROCESS_TYPE_APP,
	PROCESS_TYPE_PLUGIN,
};

char *gExecutablePath = NULL;
char *gBundleIdentifier = NULL;
int gProcessType = 0;

bool gTweakInjectionDisabled = false;
bool gAggressiveHideJBRootImages = false;
xpc_object_t gAllowedTweaks = NULL;
xpc_object_t gDeniedTweaks = NULL;
xpc_object_t gGlobalDeniedTweaks = NULL;

bool string_has_prefix(const char *str, const char* prefix)
{
	if (!str || !prefix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);

	if (str_len < prefix_len) {
		return false;
	}

	return !strncmp(str, prefix, prefix_len);
}

bool string_has_suffix(const char* str, const char* suffix)
{
	if (!str || !suffix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if (str_len < suffix_len) {
		return false;
	}

	return !strcmp(str + str_len - suffix_len, suffix);
}

char *path_copy_basename(const char *path)
{
	char pathdup[strlen(path) + 1];
	strcpy(pathdup, path);
	return strdup(basename(pathdup));
}

char *path_copy_dirname(const char *path)
{
	char pathdup[strlen(path) + 1];
	strcpy(pathdup, path);
	return strdup(dirname(pathdup));
}

static uint32_t (*dyld_image_count_orig)(void) = NULL;
static const char *(*dyld_get_image_name_orig)(uint32_t) = NULL;
static const struct mach_header *(*dyld_get_image_header_orig)(uint32_t) = NULL;
static intptr_t (*dyld_get_image_vmaddr_slide_orig)(uint32_t) = NULL;
static void (*dyld_register_func_for_add_image_orig)(void (*)(const struct mach_header *, intptr_t)) = NULL;
static void (*dyld_register_func_for_remove_image_orig)(void (*)(const struct mach_header *, intptr_t)) = NULL;
static char *(*getenv_orig)(const char *) = NULL;
static void *(*dlsym_orig)(void *, const char *) = NULL;
static int (*dladdr_orig)(const void *, Dl_info *) = NULL;
static kern_return_t (*task_info_orig)(task_name_t, task_flavor_t, task_info_t, mach_msg_type_number_t *) = NULL;
static __thread int gStealthBypassCheckDepth = 0;
static struct dyld_all_image_infos *gSanitizedAllImageInfos = NULL;
static struct dyld_image_info *gSanitizedImageInfoArray = NULL;
static uint32_t gSanitizedImageInfoCapacity = 0;
static struct dyld_uuid_info *gSanitizedUuidInfoArray = NULL;
static uint32_t gSanitizedUuidInfoCapacity = 0;
static const struct dyld_all_image_infos *gSanitizedSourceInfos = NULL;
static const struct dyld_image_info *gSanitizedSourceInfoArray = NULL;
static uint32_t gSanitizedSourceInfoCount = 0;
static const struct dyld_uuid_info *gSanitizedSourceUuidArray = NULL;
static uint32_t gSanitizedSourceUuidCount = 0;
static uint64_t gSanitizedVisibleImageGeneration = 0;
static os_unfair_lock gTaskInfoSanitizeLock = OS_UNFAIR_LOCK_INIT;

typedef void (*dyld_image_callback_t)(const struct mach_header *, intptr_t);

typedef struct {
	const struct mach_header *header;
	intptr_t slide;
	const char *path;
} stealth_visible_image_t;

typedef struct {
	const char *symbol;
	void *replacement;
} stealth_symbol_remap_t;

typedef struct {
	const void *returnAddress;
	bool bypass;
} stealth_caller_cache_entry_t;

static dyld_image_callback_t *gStealthAddImageCallbacks = NULL;
static uint32_t gStealthAddImageCallbackCount = 0;
static uint32_t gStealthAddImageCallbackCapacity = 0;
static dyld_image_callback_t *gStealthRemoveImageCallbacks = NULL;
static uint32_t gStealthRemoveImageCallbackCount = 0;
static uint32_t gStealthRemoveImageCallbackCapacity = 0;
static stealth_visible_image_t *gStealthVisibleImages = NULL;
static uint32_t gStealthVisibleImageCount = 0;
static uint32_t gStealthVisibleImageCapacity = 0;
static uint64_t gStealthVisibleImageGeneration = 1;
static os_unfair_lock gStealthDyldCallbackLock = OS_UNFAIR_LOCK_INIT;
static bool gStealthDyldBridgesInstalled = false;
static stealth_caller_cache_entry_t gStealthCallerCache[64] = {0};
static uint32_t gStealthCallerCacheNextSlot = 0;
static os_unfair_lock gStealthCallerCacheLock = OS_UNFAIR_LOCK_INIT;
static xpc_object_t gDylibDecisionCache = NULL;
static os_unfair_lock gDylibDecisionCacheLock = OS_UNFAIR_LOCK_INIT;

static kern_return_t task_info_hook(task_name_t targetTask, task_flavor_t flavor, task_info_t taskInfoOut, mach_msg_type_number_t *taskInfoOutCnt);

int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
int csops_audittoken(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token);

#define CS_VALID 0x00000001
#define CS_HARD 0x00000100
#define CS_KILL 0x00000200
#define CS_DEBUGGED 0x10000000
#define CS_OPS_STATUS 0

static bool should_enable_stealth_hiding(void)
{
	return gTweakInjectionDisabled || gAllowedTweaks;
}

static bool should_fast_block_all_tweaks(void)
{
	if (gTweakInjectionDisabled) {
		return true;
	}

	return gAllowedTweaks && xpc_array_get_count(gAllowedTweaks) == 0;
}

static bool path_is_in_aggressive_hidden_jbroot_directory(const char *path)
{
	if (!path || !gAggressiveHideJBRootImages) {
		return false;
	}

	if (gExecutablePath && !strcmp(path, gExecutablePath)) {
		return false;
	}

	static const char *activeJBRoot = NULL;
	static size_t activeJBRootLength = 0;
	static const char *varJBRoot = "/var/jb";
	static const size_t varJBRootLength = 7;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		activeJBRoot = jbroot("/");
		if (activeJBRoot) {
			activeJBRootLength = strlen(activeJBRoot);
		}
	});

	const char *relativePath = NULL;

	if (activeJBRootLength > 0 && string_has_prefix(path, activeJBRoot)) {
		relativePath = path + activeJBRootLength - 1;
	}
	else if (string_has_prefix(path, varJBRoot)) {
		relativePath = path + varJBRootLength;
	}

	if (!relativePath || relativePath[0] != '/') {
		return false;
	}

	return string_has_prefix(relativePath, "/basebin/")
		|| string_has_prefix(relativePath, "/usr/lib/")
		|| string_has_prefix(relativePath, "/Library/Frameworks/")
		|| string_has_prefix(relativePath, "/Library/MobileSubstrate/DynamicLibraries/");
}

static bool path_is_in_hidden_tweak_directory(const char *path)
{
	if (!path) return false;

	return strstr(path, "/TweakInject/")
		|| strstr(path, "/MobileSubstrate/DynamicLibraries/")
		|| strstr(path, "/DynamicPatches/")
		|| strstr(path, "/Library/Modulous/HookKit/");
}

static bool path_is_hidden_loader(const char *path)
{
	if (!path) return false;

	const char *basename = strrchr(path, '/');
	basename = basename ? &basename[1] : path;

	const char *hiddenNames[] = {
		"   Choicy.dylib",
		"Choicy.dylib",
		"AutoPatch.dylib",
		"TweakLoader.dylib",
		"shdw.dylib",
		"substitute-loader.dylib",
		"TweakInject.dylib",
		"SubstrateLoader.dylib",
		"libellekit.dylib",
		"libhooker.dylib",
		"libsandy.dylib",
		"libsonar.dylib",
		"libsubstitute.dylib",
		"libsubstrate.dylib",
		"roothideinit.dylib",
		"roothidepatch.dylib",
		"libroothide.dylib",
		"libroot.dylib",
	};

	for (uint32_t i = 0; i < sizeof(hiddenNames) / sizeof(*hiddenNames); i++) {
		if (!strcmp(basename, hiddenNames[i])) {
			return true;
		}
	}

	return string_has_prefix(basename, "systemhook-") && string_has_suffix(basename, ".dylib");
}

static bool path_is_hidden_shdw_runtime_binary(const char *path)
{
	if (!path) {
		return false;
	}

	const char *hiddenSuffixes[] = {
		"/Library/Frameworks/shdw.framework/shdw",
		"/Library/Frameworks/HookKit.framework/HookKit",
		"/Library/Frameworks/Modulous.framework/Modulous",
		"/Library/Frameworks/RootBridge.framework/RootBridge",
		"/Library/Modulous/HookKit/HookKitFishhookModule.bundle/HookKitFishhookModule",
		"/Library/Modulous/HookKit/HookKitElleKitModule.bundle/HookKitElleKitModule",
		"/Library/Modulous/HookKit/HookKitDobbyModule.bundle/HookKitDobbyModule",
	};

	for (uint32_t i = 0; i < sizeof(hiddenSuffixes) / sizeof(*hiddenSuffixes); i++) {
		if (string_has_suffix(path, hiddenSuffixes[i])) {
			return true;
		}
	}

	return false;
}

static bool path_is_in_tweak_injection_directory(const char *path)
{
	if (!path) {
		return false;
	}

	return strstr(path, "/TweakInject/") || strstr(path, "/MobileSubstrate/DynamicLibraries/");
}

static bool path_has_neighbor_plist(const char *dylibPath)
{
	if (!dylibPath || !string_has_suffix(dylibPath, ".dylib")) {
		return false;
	}

	size_t dylibPathLength = strlen(dylibPath) + 1;
	char plistPath[dylibPathLength];
	strcpy(plistPath, dylibPath);
	strlcpy(&plistPath[dylibPathLength - 6], "plist", 6);
	return access(plistPath, R_OK) == 0;
}

static bool path_is_probable_tweak(const char *dylibPath)
{
	return path_is_in_tweak_injection_directory(dylibPath) && path_has_neighbor_plist(dylibPath);
}

static bool dylib_decision_cache_get(const char *path, bool *decisionOut)
{
	if (!path || !decisionOut) {
		return false;
	}

	bool found = false;
	os_unfair_lock_lock(&gDylibDecisionCacheLock);
	if (gDylibDecisionCache) {
		xpc_object_t cachedValue = xpc_dictionary_get_value(gDylibDecisionCache, path);
		if (cachedValue && xpc_get_type(cachedValue) == XPC_TYPE_BOOL) {
			*decisionOut = xpc_bool_get_value(cachedValue);
			found = true;
		}
	}
	os_unfair_lock_unlock(&gDylibDecisionCacheLock);
	return found;
}

static void dylib_decision_cache_set(const char *path, bool decision)
{
	if (!path) {
		return;
	}

	os_unfair_lock_lock(&gDylibDecisionCacheLock);
	if (!gDylibDecisionCache) {
		gDylibDecisionCache = xpc_dictionary_create(NULL, NULL, 0);
	}
	if (gDylibDecisionCache) {
		xpc_dictionary_set_bool(gDylibDecisionCache, path, decision);
	}
	os_unfair_lock_unlock(&gDylibDecisionCacheLock);
}

static bool caller_bypass_cache_get(const void *returnAddress, bool *decisionOut)
{
	if (!returnAddress || !decisionOut) {
		return false;
	}

	bool found = false;
	os_unfair_lock_lock(&gStealthCallerCacheLock);
	for (uint32_t i = 0; i < sizeof(gStealthCallerCache) / sizeof(*gStealthCallerCache); i++) {
		if (gStealthCallerCache[i].returnAddress == returnAddress) {
			*decisionOut = gStealthCallerCache[i].bypass;
			found = true;
			break;
		}
	}
	os_unfair_lock_unlock(&gStealthCallerCacheLock);
	return found;
}

static void caller_bypass_cache_set(const void *returnAddress, bool bypass)
{
	if (!returnAddress) {
		return;
	}

	os_unfair_lock_lock(&gStealthCallerCacheLock);
	for (uint32_t i = 0; i < sizeof(gStealthCallerCache) / sizeof(*gStealthCallerCache); i++) {
		if (gStealthCallerCache[i].returnAddress == returnAddress) {
			gStealthCallerCache[i].bypass = bypass;
			os_unfair_lock_unlock(&gStealthCallerCacheLock);
			return;
		}
	}

	uint32_t slot = gStealthCallerCacheNextSlot++ % (sizeof(gStealthCallerCache) / sizeof(*gStealthCallerCache));
	gStealthCallerCache[slot] = (stealth_caller_cache_entry_t){
		.returnAddress = returnAddress,
		.bypass = bypass,
	};
	os_unfair_lock_unlock(&gStealthCallerCacheLock);
}

static bool should_hide_from_app(const char *path)
{
	if (!should_enable_stealth_hiding()) {
		return false;
	}

	return path_is_in_aggressive_hidden_jbroot_directory(path)
		|| path_is_in_hidden_tweak_directory(path)
		|| path_is_hidden_loader(path)
		|| path_is_hidden_shdw_runtime_binary(path);
}

static bool should_hide_env_name(const char *name)
{
	if (!name || !should_enable_stealth_hiding()) {
		return false;
	}

	return !strcmp(name, "DYLD_INSERT_LIBRARIES")
		|| !strcmp(name, "_MSSafeMode")
		|| !strcmp(name, "_SafeMode")
		|| !strcmp(name, "_SubstituteSafeMode")
		|| !strcmp(name, "_ChoicyInjectionEnabledFromSpringBoard");
}

static int resolve_dladdr(const void *addr, Dl_info *info)
{
	if (dladdr_orig) {
		return dladdr_orig(addr, info);
	}
	return dladdr(addr, info);
}

static const char *path_for_mach_header_in_infos(const struct dyld_all_image_infos *infos, const struct mach_header *header)
{
	if (!header) {
		return NULL;
	}

	if (infos && infos->infoArray) {
		for (uint32_t i = 0; i < infos->infoArrayCount; i++) {
			const struct dyld_image_info *entry = &infos->infoArray[i];
			if (entry->imageLoadAddress == header) {
				return entry->imageFilePath;
			}
		}
	}

	os_unfair_lock_lock(&gStealthDyldCallbackLock);
	for (uint32_t i = 0; i < gStealthVisibleImageCount; i++) {
		if (gStealthVisibleImages[i].header == header) {
			const char *path = gStealthVisibleImages[i].path;
			os_unfair_lock_unlock(&gStealthDyldCallbackLock);
			return path;
		}
	}
	os_unfair_lock_unlock(&gStealthDyldCallbackLock);

	Dl_info info = {0};
	if (resolve_dladdr(header, &info) == 0) {
		return NULL;
	}
	return info.dli_fname;
}

static bool should_hide_mach_header_from_app(const struct dyld_all_image_infos *infos, const struct mach_header *header)
{
	const char *path = path_for_mach_header_in_infos(infos, header);
	return should_hide_from_app(path);
}

static bool caller_should_bypass_hiding(const void *returnAddress)
{
	if (!should_enable_stealth_hiding()) {
		return false;
	}

	if (gStealthBypassCheckDepth > 0) {
		return true;
	}

	if (!returnAddress) {
		return false;
	}

	bool cachedBypass = false;
	if (caller_bypass_cache_get(returnAddress, &cachedBypass)) {
		return cachedBypass;
	}

	Dl_info callerInfo = {0};
	gStealthBypassCheckDepth++;
	int dladdrResult = resolve_dladdr(returnAddress, &callerInfo);
	gStealthBypassCheckDepth--;
	if (dladdrResult == 0 || !callerInfo.dli_fname) {
		return false;
	}

	bool shouldBypass = path_is_in_aggressive_hidden_jbroot_directory(callerInfo.dli_fname)
		|| path_is_hidden_loader(callerInfo.dli_fname)
		|| path_is_in_hidden_tweak_directory(callerInfo.dli_fname);
	caller_bypass_cache_set(returnAddress, shouldBypass);
	return shouldBypass;
}

static bool ensure_stealth_buffer_capacity(void **buffer, uint32_t *capacity, uint32_t requiredCount, size_t elementSize)
{
	if (requiredCount <= *capacity) {
		return true;
	}

	uint32_t newCapacity = *capacity ? *capacity : 8;
	while (newCapacity < requiredCount) {
		newCapacity *= 2;
	}

	void *newBuffer = realloc(*buffer, elementSize * newCapacity);
	if (!newBuffer) {
		return false;
	}

	*buffer = newBuffer;
	*capacity = newCapacity;
	return true;
}

static uint32_t stealth_visible_image_count(void)
{
	os_unfair_lock_lock(&gStealthDyldCallbackLock);
	uint32_t count = gStealthVisibleImageCount;
	os_unfair_lock_unlock(&gStealthDyldCallbackLock);
	return count;
}

static uint64_t stealth_visible_image_generation(void)
{
	os_unfair_lock_lock(&gStealthDyldCallbackLock);
	uint64_t generation = gStealthVisibleImageGeneration;
	os_unfair_lock_unlock(&gStealthDyldCallbackLock);
	return generation;
}

static bool stealth_visible_image_get(uint32_t index, stealth_visible_image_t *imageOut)
{
	if (!imageOut) {
		return false;
	}

	os_unfair_lock_lock(&gStealthDyldCallbackLock);
	if (index >= gStealthVisibleImageCount) {
		os_unfair_lock_unlock(&gStealthDyldCallbackLock);
		return false;
	}

	*imageOut = gStealthVisibleImages[index];
	os_unfair_lock_unlock(&gStealthDyldCallbackLock);
	return true;
}

static bool stealth_visible_images_add_locked(const struct mach_header *header, intptr_t slide, const char *path)
{
	for (uint32_t i = 0; i < gStealthVisibleImageCount; i++) {
		if (gStealthVisibleImages[i].header == header) {
			if (gStealthVisibleImages[i].slide != slide || gStealthVisibleImages[i].path != path) {
				gStealthVisibleImages[i].slide = slide;
				gStealthVisibleImages[i].path = path;
				gStealthVisibleImageGeneration++;
			}
			return true;
		}
	}

	if (!ensure_stealth_buffer_capacity((void **)&gStealthVisibleImages, &gStealthVisibleImageCapacity, gStealthVisibleImageCount + 1, sizeof(*gStealthVisibleImages))) {
		return false;
	}

	gStealthVisibleImages[gStealthVisibleImageCount++] = (stealth_visible_image_t){
		.header = header,
		.slide = slide,
		.path = path,
	};
	gStealthVisibleImageGeneration++;
	return true;
}

static bool stealth_visible_images_remove_locked(const struct mach_header *header)
{
	for (uint32_t i = 0; i < gStealthVisibleImageCount; i++) {
		if (gStealthVisibleImages[i].header == header) {
			gStealthVisibleImages[i] = gStealthVisibleImages[gStealthVisibleImageCount - 1];
			gStealthVisibleImageCount--;
			gStealthVisibleImageGeneration++;
			return true;
		}
	}

	return false;
}

static dyld_image_callback_t *copy_dyld_callbacks_locked(dyld_image_callback_t *callbacks, uint32_t callbackCount)
{
	if (callbackCount == 0 || !callbacks) {
		return NULL;
	}

	size_t callbackBytes = sizeof(*callbacks) * callbackCount;
	dyld_image_callback_t *snapshot = malloc(callbackBytes);
	if (!snapshot) {
		return NULL;
	}

	memcpy(snapshot, callbacks, callbackBytes);
	return snapshot;
}

static stealth_visible_image_t *copy_visible_images_locked(uint32_t *imageCountOut)
{
	if (imageCountOut) {
		*imageCountOut = gStealthVisibleImageCount;
	}

	if (gStealthVisibleImageCount == 0 || !gStealthVisibleImages) {
		return NULL;
	}

	size_t imageBytes = sizeof(*gStealthVisibleImages) * gStealthVisibleImageCount;
	stealth_visible_image_t *snapshot = malloc(imageBytes);
	if (!snapshot) {
		if (imageCountOut) {
			*imageCountOut = 0;
		}
		return NULL;
	}

	memcpy(snapshot, gStealthVisibleImages, imageBytes);
	return snapshot;
}

static void dispatch_dyld_callbacks(dyld_image_callback_t *callbacks, uint32_t callbackCount, const struct mach_header *header, intptr_t slide)
{
	for (uint32_t i = 0; i < callbackCount; i++) {
		callbacks[i](header, slide);
	}
}

static void stealth_add_image_bridge(const struct mach_header *header, intptr_t slide)
{
	const char *path = path_for_mach_header_in_infos(NULL, header);
	if (should_hide_from_app(path)) {
		return;
	}

	dyld_image_callback_t *callbacks = NULL;
	uint32_t callbackCount = 0;

	os_unfair_lock_lock(&gStealthDyldCallbackLock);
	stealth_visible_images_add_locked(header, slide, path);
	callbackCount = gStealthAddImageCallbackCount;
	callbacks = copy_dyld_callbacks_locked(gStealthAddImageCallbacks, callbackCount);
	os_unfair_lock_unlock(&gStealthDyldCallbackLock);

	if (callbacks) {
		dispatch_dyld_callbacks(callbacks, callbackCount, header, slide);
		free(callbacks);
	}
}

static void stealth_remove_image_bridge(const struct mach_header *header, intptr_t slide)
{
	dyld_image_callback_t *callbacks = NULL;
	uint32_t callbackCount = 0;

	os_unfair_lock_lock(&gStealthDyldCallbackLock);
	bool shouldNotify = stealth_visible_images_remove_locked(header);
	if (shouldNotify) {
		callbackCount = gStealthRemoveImageCallbackCount;
		callbacks = copy_dyld_callbacks_locked(gStealthRemoveImageCallbacks, callbackCount);
	}
	os_unfair_lock_unlock(&gStealthDyldCallbackLock);

	if (callbacks) {
		dispatch_dyld_callbacks(callbacks, callbackCount, header, slide);
		free(callbacks);
	}
}

static uint32_t dyld_image_count_hook(void)
{
	if (!dyld_image_count_orig) {
		return 0;
	}

	if (caller_should_bypass_hiding(__builtin_extract_return_addr(__builtin_return_address(0)))) {
		return dyld_image_count_orig();
	}

	return stealth_visible_image_count();
}

static const char *dyld_get_image_name_hook(uint32_t idx)
{
	if (!dyld_get_image_name_orig) {
		return NULL;
	}

	if (caller_should_bypass_hiding(__builtin_extract_return_addr(__builtin_return_address(0)))) {
		return dyld_get_image_name_orig(idx);
	}

	stealth_visible_image_t visibleImage = {0};
	return stealth_visible_image_get(idx, &visibleImage) ? visibleImage.path : NULL;
}

static const struct mach_header *dyld_get_image_header_hook(uint32_t idx)
{
	if (!dyld_get_image_header_orig) {
		return NULL;
	}

	if (caller_should_bypass_hiding(__builtin_extract_return_addr(__builtin_return_address(0)))) {
		return dyld_get_image_header_orig(idx);
	}

	stealth_visible_image_t visibleImage = {0};
	return stealth_visible_image_get(idx, &visibleImage) ? visibleImage.header : NULL;
}

static intptr_t dyld_get_image_vmaddr_slide_hook(uint32_t idx)
{
	if (!dyld_get_image_vmaddr_slide_orig) {
		return 0;
	}

	if (caller_should_bypass_hiding(__builtin_extract_return_addr(__builtin_return_address(0)))) {
		return dyld_get_image_vmaddr_slide_orig(idx);
	}

	stealth_visible_image_t visibleImage = {0};
	return stealth_visible_image_get(idx, &visibleImage) ? visibleImage.slide : 0;
}

static void dyld_register_func_for_add_image_hook(void (*func)(const struct mach_header *, intptr_t))
{
	if (!func) {
		if (dyld_register_func_for_add_image_orig) {
			dyld_register_func_for_add_image_orig(func);
		}
		return;
	}

	if (caller_should_bypass_hiding(__builtin_extract_return_addr(__builtin_return_address(0)))) {
		if (dyld_register_func_for_add_image_orig) {
			dyld_register_func_for_add_image_orig(func);
		}
		return;
	}

	bool stored = false;
	stealth_visible_image_t *visibleImages = NULL;
	uint32_t visibleImageCount = 0;

	os_unfair_lock_lock(&gStealthDyldCallbackLock);
	if (ensure_stealth_buffer_capacity((void **)&gStealthAddImageCallbacks, &gStealthAddImageCallbackCapacity, gStealthAddImageCallbackCount + 1, sizeof(*gStealthAddImageCallbacks))) {
		gStealthAddImageCallbacks[gStealthAddImageCallbackCount++] = func;
		stored = true;
		visibleImages = copy_visible_images_locked(&visibleImageCount);
	}
	os_unfair_lock_unlock(&gStealthDyldCallbackLock);

	if (!stored) {
		if (dyld_register_func_for_add_image_orig) {
			dyld_register_func_for_add_image_orig(func);
		}
		return;
	}

	for (uint32_t i = 0; i < visibleImageCount; i++) {
		func(visibleImages[i].header, visibleImages[i].slide);
	}

	free(visibleImages);
}

static void dyld_register_func_for_remove_image_hook(void (*func)(const struct mach_header *, intptr_t))
{
	if (!func) {
		if (dyld_register_func_for_remove_image_orig) {
			dyld_register_func_for_remove_image_orig(func);
		}
		return;
	}

	if (caller_should_bypass_hiding(__builtin_extract_return_addr(__builtin_return_address(0)))) {
		if (dyld_register_func_for_remove_image_orig) {
			dyld_register_func_for_remove_image_orig(func);
		}
		return;
	}

	bool stored = false;
	os_unfair_lock_lock(&gStealthDyldCallbackLock);
	if (ensure_stealth_buffer_capacity((void **)&gStealthRemoveImageCallbacks, &gStealthRemoveImageCallbackCapacity, gStealthRemoveImageCallbackCount + 1, sizeof(*gStealthRemoveImageCallbacks))) {
		gStealthRemoveImageCallbacks[gStealthRemoveImageCallbackCount++] = func;
		stored = true;
	}
	os_unfair_lock_unlock(&gStealthDyldCallbackLock);

	if (!stored && dyld_register_func_for_remove_image_orig) {
		dyld_register_func_for_remove_image_orig(func);
	}
}

static char *getenv_hook(const char *name)
{
	if (!name) {
		return NULL;
	}

	if (getenv_orig && caller_should_bypass_hiding(__builtin_extract_return_addr(__builtin_return_address(0)))) {
		return getenv_orig(name);
	}

	if (should_hide_env_name(name)) {
		os_log_dbg("Hiding %{public}s from getenv()", name);
		return NULL;
	}

	return getenv_orig ? getenv_orig(name) : NULL;
}

static int dladdr_hook(const void *addr, Dl_info *info)
{
	if (caller_should_bypass_hiding(__builtin_extract_return_addr(__builtin_return_address(0)))) {
		return resolve_dladdr(addr, info);
	}

	int result = resolve_dladdr(addr, info);
	if (!result || !info || !info->dli_fname || !should_hide_from_app(info->dli_fname)) {
		return result;
	}

	info->dli_fname = gExecutablePath;
	info->dli_fbase = (void *)_dyld_get_image_header(0);
	info->dli_sname = NULL;
	info->dli_saddr = NULL;
	return 1;
}

static void *dlsym_hook(void *handle, const char *symbol)
{
	if (!dlsym_orig || !symbol) {
		return dlsym_orig ? dlsym_orig(handle, symbol) : NULL;
	}

	if (caller_should_bypass_hiding(__builtin_extract_return_addr(__builtin_return_address(0)))) {
		return dlsym_orig(handle, symbol);
	}

	static const stealth_symbol_remap_t remaps[] = {
		{ "_dyld_image_count", (void *)dyld_image_count_hook },
		{ "_dyld_get_image_name", (void *)dyld_get_image_name_hook },
		{ "_dyld_get_image_header", (void *)dyld_get_image_header_hook },
		{ "_dyld_get_image_vmaddr_slide", (void *)dyld_get_image_vmaddr_slide_hook },
		{ "_dyld_register_func_for_add_image", (void *)dyld_register_func_for_add_image_hook },
		{ "_dyld_register_func_for_remove_image", (void *)dyld_register_func_for_remove_image_hook },
		{ "getenv", (void *)getenv_hook },
		{ "dladdr", (void *)dladdr_hook },
		{ "task_info", (void *)task_info_hook },
	};

	for (uint32_t i = 0; i < sizeof(remaps) / sizeof(*remaps); i++) {
		if (!strcmp(symbol, remaps[i].symbol)) {
			return remaps[i].replacement;
		}
	}

	return dlsym_orig(handle, symbol);
}

static void sanitize_task_dyld_info_in_place(task_info_t taskInfoOut, mach_msg_type_number_t taskInfoOutCnt)
{
	if (!taskInfoOut || taskInfoOutCnt < TASK_DYLD_INFO_COUNT) {
		return;
	}

	task_dyld_info_data_t *dyldInfo = (task_dyld_info_data_t *)taskInfoOut;
	if (dyldInfo->all_image_info_addr == 0) {
		return;
	}

	struct dyld_all_image_infos *realInfos = (struct dyld_all_image_infos *)(uintptr_t)dyldInfo->all_image_info_addr;
	if (!realInfos || !realInfos->infoArray || realInfos->infoArrayCount == 0) {
		return;
	}

	uint32_t sourceUuidCount = (realInfos->version >= 8 && realInfos->uuidArray) ? (uint32_t)realInfos->uuidArrayCount : 0;
	uint64_t visibleImageGeneration = stealth_visible_image_generation();

	os_unfair_lock_lock(&gTaskInfoSanitizeLock);

	if (!gSanitizedAllImageInfos) {
		gSanitizedAllImageInfos = calloc(1, sizeof(*gSanitizedAllImageInfos));
		if (!gSanitizedAllImageInfos) {
			os_unfair_lock_unlock(&gTaskInfoSanitizeLock);
			return;
		}
	}

	if (gSanitizedVisibleImageGeneration == visibleImageGeneration
		&& gSanitizedSourceInfos == realInfos
		&& gSanitizedSourceInfoArray == realInfos->infoArray
		&& gSanitizedSourceInfoCount == realInfos->infoArrayCount
		&& gSanitizedSourceUuidArray == realInfos->uuidArray
		&& gSanitizedSourceUuidCount == sourceUuidCount) {
		dyldInfo->all_image_info_addr = (mach_vm_address_t)(uintptr_t)gSanitizedAllImageInfos;
		dyldInfo->all_image_info_size = (mach_vm_size_t)sizeof(*gSanitizedAllImageInfos);
		os_unfair_lock_unlock(&gTaskInfoSanitizeLock);
		return;
	}

	if (realInfos->infoArrayCount > gSanitizedImageInfoCapacity) {
		struct dyld_image_info *newInfoArray = realloc(gSanitizedImageInfoArray, sizeof(*gSanitizedImageInfoArray) * realInfos->infoArrayCount);
		if (!newInfoArray) {
			os_unfair_lock_unlock(&gTaskInfoSanitizeLock);
			return;
		}
		gSanitizedImageInfoArray = newInfoArray;
		gSanitizedImageInfoCapacity = realInfos->infoArrayCount;
	}

	uint32_t visibleInfoCount = 0;
	for (uint32_t i = 0; i < realInfos->infoArrayCount; i++) {
		const struct dyld_image_info *entry = &realInfos->infoArray[i];
		if (should_hide_from_app(entry->imageFilePath)) {
			continue;
		}
		gSanitizedImageInfoArray[visibleInfoCount++] = *entry;
	}

	uint32_t visibleUuidCount = 0;
	bool hasUuidArray = realInfos->version >= 8 && realInfos->uuidArray && realInfos->uuidArrayCount > 0;
	if (hasUuidArray) {
		if (realInfos->uuidArrayCount > gSanitizedUuidInfoCapacity) {
			struct dyld_uuid_info *newUuidArray = realloc(gSanitizedUuidInfoArray, sizeof(*gSanitizedUuidInfoArray) * realInfos->uuidArrayCount);
			if (!newUuidArray) {
				os_unfair_lock_unlock(&gTaskInfoSanitizeLock);
				return;
			}
			gSanitizedUuidInfoArray = newUuidArray;
			gSanitizedUuidInfoCapacity = (uint32_t)realInfos->uuidArrayCount;
		}

		for (uintptr_t i = 0; i < realInfos->uuidArrayCount; i++) {
			const struct dyld_uuid_info *entry = &realInfos->uuidArray[i];
			if (should_hide_mach_header_from_app(realInfos, entry->imageLoadAddress)) {
				continue;
			}
			gSanitizedUuidInfoArray[visibleUuidCount++] = *entry;
		}
	}

	*gSanitizedAllImageInfos = *realInfos;
	gSanitizedAllImageInfos->infoArray = gSanitizedImageInfoArray;
	gSanitizedAllImageInfos->infoArrayCount = visibleInfoCount;
	if (realInfos->version >= 8) {
		gSanitizedAllImageInfos->uuidArray = hasUuidArray ? gSanitizedUuidInfoArray : NULL;
		gSanitizedAllImageInfos->uuidArrayCount = visibleUuidCount;
	}
	if (realInfos->version >= 9) {
		gSanitizedAllImageInfos->dyldAllImageInfosAddress = gSanitizedAllImageInfos;
	}

	dyldInfo->all_image_info_addr = (mach_vm_address_t)(uintptr_t)gSanitizedAllImageInfos;
	dyldInfo->all_image_info_size = (mach_vm_size_t)sizeof(*gSanitizedAllImageInfos);
	gSanitizedSourceInfos = realInfos;
	gSanitizedSourceInfoArray = realInfos->infoArray;
	gSanitizedSourceInfoCount = realInfos->infoArrayCount;
	gSanitizedSourceUuidArray = realInfos->uuidArray;
	gSanitizedSourceUuidCount = sourceUuidCount;
	gSanitizedVisibleImageGeneration = visibleImageGeneration;

	os_unfair_lock_unlock(&gTaskInfoSanitizeLock);
}

static kern_return_t task_info_hook(task_name_t targetTask, task_flavor_t flavor, task_info_t taskInfoOut, mach_msg_type_number_t *taskInfoOutCnt)
{
	if (!task_info_orig) {
		return KERN_FAILURE;
	}

	if (caller_should_bypass_hiding(__builtin_extract_return_addr(__builtin_return_address(0)))) {
		return task_info_orig(targetTask, flavor, taskInfoOut, taskInfoOutCnt);
	}

	kern_return_t kr = task_info_orig(targetTask, flavor, taskInfoOut, taskInfoOutCnt);
	if (kr != KERN_SUCCESS || flavor != TASK_DYLD_INFO || targetTask != mach_task_self()) {
		return kr;
	}

	sanitize_task_dyld_info_in_place(taskInfoOut, taskInfoOutCnt ? *taskInfoOutCnt : 0);
	return kr;
}

static void apply_stealth_csops_flags(unsigned int ops, pid_t pid, void *useraddr, size_t usersize, const void *returnAddress)
{
	if (ops != CS_OPS_STATUS || pid != getpid() || usersize < sizeof(uint32_t) || !useraddr) {
		return;
	}

	if (!should_enable_stealth_hiding()) {
		return;
	}

	if (caller_should_bypass_hiding(returnAddress)) {
		return;
	}

	uint32_t *flags = (uint32_t *)useraddr;

	// Mirror the hardened view detectors expect without touching the kernel-side state.
	*flags |= (CS_VALID | CS_HARD | CS_KILL);
	*flags &= ~CS_DEBUGGED;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static int csops_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize)
{
	int rv = syscall(SYS_csops, pid, ops, useraddr, usersize);
	if (rv == 0) {
		apply_stealth_csops_flags(ops, pid, useraddr, usersize, __builtin_extract_return_addr(__builtin_return_address(0)));
	}
	return rv;
}

static int csops_audittoken_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token)
{
	int rv = syscall(SYS_csops_audittoken, pid, ops, useraddr, usersize, token);
	if (rv == 0) {
		apply_stealth_csops_flags(ops, pid, useraddr, usersize, __builtin_extract_return_addr(__builtin_return_address(0)));
	}
	return rv;
}
#pragma clang diagnostic pop

static void install_stealth_hiding_hooks(void)
{
	struct rebinding dyldRebindings[] = {
		{ "_dyld_image_count", (void *)dyld_image_count_hook, (void **)&dyld_image_count_orig },
		{ "_dyld_get_image_name", (void *)dyld_get_image_name_hook, (void **)&dyld_get_image_name_orig },
		{ "_dyld_get_image_header", (void *)dyld_get_image_header_hook, (void **)&dyld_get_image_header_orig },
		{ "_dyld_get_image_vmaddr_slide", (void *)dyld_get_image_vmaddr_slide_hook, (void **)&dyld_get_image_vmaddr_slide_orig },
		{ "_dyld_register_func_for_add_image", (void *)dyld_register_func_for_add_image_hook, (void **)&dyld_register_func_for_add_image_orig },
		{ "_dyld_register_func_for_remove_image", (void *)dyld_register_func_for_remove_image_hook, (void **)&dyld_register_func_for_remove_image_orig },
		{ "getenv", (void *)getenv_hook, (void **)&getenv_orig },
		{ "dlsym", (void *)dlsym_hook, (void **)&dlsym_orig },
		{ "dladdr", (void *)dladdr_hook, (void **)&dladdr_orig },
		{ "task_info", (void *)task_info_hook, (void **)&task_info_orig },
	};

	int r = rebind_symbols(dyldRebindings, sizeof(dyldRebindings) / sizeof(*dyldRebindings));
	if (r != 0) {
		os_log_err("Failed to install stealth hiding hooks: %d", r);
	}

	if (!gStealthDyldBridgesInstalled) {
		gStealthDyldBridgesInstalled = true;
		if (dyld_register_func_for_add_image_orig) {
			dyld_register_func_for_add_image_orig(stealth_add_image_bridge);
		}
		if (dyld_register_func_for_remove_image_orig) {
			dyld_register_func_for_remove_image_orig(stealth_remove_image_bridge);
		}
	}

	if (litehook_hook_function((void *)csops, (void *)csops_hook) != KERN_SUCCESS) {
		os_log_err("Failed to install csops stealth hook");
	}

	if (litehook_hook_function((void *)csops_audittoken, (void *)csops_audittoken_hook) != KERN_SUCCESS) {
		os_log_err("Failed to install csops_audittoken stealth hook");
	}
}

static void scrub_stealth_environment(void)
{
	if (!should_enable_stealth_hiding()) {
		return;
	}

	const char *namesToUnset[] = {
		"_MSSafeMode",
		"_SafeMode",
		"_SubstituteSafeMode",
		"_ChoicyInjectionEnabledFromSpringBoard",
	};

	for (uint32_t i = 0; i < sizeof(namesToUnset) / sizeof(*namesToUnset); i++) {
		unsetenv(namesToUnset[i]);
	}
}

xpc_object_t xpc_object_from_plist(const char *path)
{
	int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;

    struct stat st = {0};
    if (fstat(fd, &st) != 0 || st.st_size == 0) {
        close(fd);
        return NULL;
    }

    void *data = mmap(NULL, st.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) return NULL;

    xpc_object_t plist = xpc_create_from_plist(data, st.st_size);
    if (plist == NULL) {
        char *plist_str = (char *)data;
        if (strnstr(plist_str, "bplist", st.st_size) ||
            strnstr(plist_str, "?xml", st.st_size) ||
            strnstr(plist_str, "!DOCTYPE plist", st.st_size)) {
            munmap(data, st.st_size);
            return NULL;
        }

        for (int i = 0; i < st.st_size; i++) {
            if (plist_str[i] < 0 || plist_str[i] > 127) {
                munmap(data, st.st_size);
                return NULL;
            }
        }

        nextstep_plist_t nextstep_plist = {0};
        nextstep_plist.index = 0;
        nextstep_plist.size = st.st_size;
        nextstep_plist.data = plist_str;
        plist = nxp_parse_object(&nextstep_plist);
    }

    munmap(data, st.st_size);
    return plist;
}

bool xpc_array_contains_string(xpc_object_t xArr, const char *string)
{
	if (!xArr) return false;

	__block bool found = false;
	xpc_array_apply(xArr, ^bool(size_t index, xpc_object_t value){
		if (xpc_get_type(value) == XPC_TYPE_STRING) {
			const char *thisString = xpc_string_get_string_ptr(value);
			if (!strcmp(thisString, string)) {
				found = true;
				return false;
			}
		}
		return true;
	});
	return found;
}

void parse_allow_deny_list(const char *listStr, xpc_object_t *arrOut)
{
	if (!listStr || !arrOut) return;

	xpc_object_t xArr = xpc_array_create(NULL, 0);
	char *listStrCopy = strdup(listStr);
	char *curString = strtok(listStrCopy, ":");
	while (curString != NULL) {
		xpc_array_set_string(xArr, XPC_ARRAY_APPEND, curString);
		curString = strtok(NULL, ":");
	}
	free(listStrCopy);

	*arrOut = xArr;
}

void load_global_preferences(xpc_object_t preferencesXdict, xpc_object_t processPreferencesXdict)
{
	bool overwriteGlobalConfig = false;
	char *overwriteEnvConfigStr = getenv(kEnvOverwriteGlobalConfigurationOverride);
	if (overwriteEnvConfigStr) {
		overwriteGlobalConfig = !strcmp(overwriteEnvConfigStr, "1");
	}
	else if (processPreferencesXdict && xpc_get_type(processPreferencesXdict) == XPC_TYPE_DICTIONARY) {
		overwriteGlobalConfig = xpc_dictionary_get_bool(processPreferencesXdict, kChoicyProcessPrefsKeyOverwriteGlobalTweakConfiguration);
	}

	if (!overwriteGlobalConfig) {
		xpc_object_t globalDeniedTweaks = xpc_dictionary_get_value(preferencesXdict, kChoicyPrefsKeyGlobalDeniedTweaks);
		if (globalDeniedTweaks && xpc_get_type(globalDeniedTweaks) == XPC_TYPE_ARRAY) {
			gGlobalDeniedTweaks = xpc_retain(globalDeniedTweaks);
		}
	}
}

void load_process_preferences(xpc_object_t preferencesXdict, xpc_object_t processPreferencesXdict)
{
	// There are two possible cases how we can get here with kChoicyProcessPrefsKeyTweakInjectionDisabled=true in the plist
	// (Since normally that option will also prevent this dylib from injecting, meaning our code would not execute in the first place)
	// 1) The process is not an app spawned by SpringBoard (Since we can only set _SafeMode variables from SpringBoard/runningboardd)
	// 2) The process was launched via the "Launch with Tweaks" haptic touch option on SpringBoard
	// We can differentiate between the two, because 2) will also set the "_ChoicyInjectionEnabledFromSpringBoard" env variable
	if (getenv("_ChoicyInjectionEnabledFromSpringBoard")) {
		gTweakInjectionDisabled = false;
	}
	else {
		gTweakInjectionDisabled = xpc_dictionary_get_bool(processPreferencesXdict, kChoicyProcessPrefsKeyTweakInjectionDisabled);
	}

	bool customTweakConfigurationEnabled = xpc_dictionary_get_bool(processPreferencesXdict, kChoicyProcessPrefsKeyCustomTweakConfigurationEnabled);
	gAggressiveHideJBRootImages = xpc_dictionary_get_bool(processPreferencesXdict, kChoicyProcessPrefsKeyAggressiveHideJBRootImages);
	if (customTweakConfigurationEnabled) {
		int allowDenyMode = 1;
		xpc_object_t allowDenyModeVal = xpc_dictionary_get_value(processPreferencesXdict, kChoicyProcessPrefsKeyAllowDenyMode);
		if (allowDenyModeVal && xpc_get_type(allowDenyModeVal) == XPC_TYPE_INT64) {
			allowDenyMode = xpc_int64_get_value(allowDenyModeVal);
		}

		if (allowDenyMode == 2) { // DENY
			xpc_object_t deniedTweaks = xpc_dictionary_get_value(processPreferencesXdict, kChoicyProcessPrefsKeyDeniedTweaks);
			if (deniedTweaks && xpc_get_type(deniedTweaks) == XPC_TYPE_ARRAY) {
				gDeniedTweaks = xpc_retain(deniedTweaks);
			}
		}
		else if (allowDenyMode == 1) { // ALLOW
			xpc_object_t allowedTweaks = xpc_dictionary_get_value(processPreferencesXdict, kChoicyProcessPrefsKeyAllowedTweaks);
			if (allowedTweaks && xpc_get_type(allowedTweaks) == XPC_TYPE_ARRAY) {
				gAllowedTweaks = xpc_retain(allowedTweaks);
			}
		}
	}
}

void load_process_info(void)
{
	// Load executable path
	uint32_t executablePathSize = 0;
	_NSGetExecutablePath(NULL, &executablePathSize);
	gExecutablePath = malloc(executablePathSize);
	_NSGetExecutablePath(gExecutablePath, &executablePathSize);

	// Calling os_log from inside logd or notifyd deadlocks the system, prevent that...
	if (!strcmp(gExecutablePath, "/usr/libexec/logd") || !strcmp(gExecutablePath, "/usr/sbin/notifyd")) gShouldLog = false;

	// Load process type
	char *executableDir = path_copy_dirname(gExecutablePath);
	if (string_has_suffix(executableDir, ".app"))		 gProcessType = PROCESS_TYPE_APP;
	else if (string_has_suffix(executableDir, ".appex")) gProcessType = PROCESS_TYPE_PLUGIN;
	else												 gProcessType = PROCESS_TYPE_BINARY;

	os_log_dbg("Identified process type: %d\n", gProcessType);

	// Load application identifier
	size_t infoPlistPathSize = strlen(executableDir) + strlen("/Info.plist") + 1;
	char infoPlistPath[infoPlistPathSize];
	strlcpy(infoPlistPath, executableDir, infoPlistPathSize);
	strlcat(infoPlistPath, "/Info.plist", infoPlistPathSize);
	free(executableDir);
	if ((gProcessType == PROCESS_TYPE_APP || gProcessType == PROCESS_TYPE_PLUGIN) && access(infoPlistPath, R_OK) == 0) {
		xpc_object_t infoXdict = xpc_object_from_plist(infoPlistPath);
		if (infoXdict && xpc_get_type(infoXdict) == XPC_TYPE_DICTIONARY) {
			const char *bundleIdentifier = xpc_dictionary_get_string(infoXdict, "CFBundleIdentifier");
			if (bundleIdentifier) {
				gBundleIdentifier = strdup(bundleIdentifier);
				os_log_dbg("Identified bundle identifier: %{PUBLIC}s", gBundleIdentifier);
			}
			xpc_release(infoXdict);
		}
	}

	// Load overwrites from environment
	parse_allow_deny_list(getenv(kEnvDeniedTweaksOverride), &gDeniedTweaks);
	parse_allow_deny_list(getenv(kEnvAllowedTweaksOverride), &gAllowedTweaks);

	if (gDeniedTweaks && gShouldLog && os_log_debug_enabled(OS_LOG_DEFAULT)) {
		char *gDeniedTweaksDesc = xpc_copy_description(gDeniedTweaks);
		os_log_dbg("Loaded denied tweaks from environment: %{PUBLIC}s", gDeniedTweaksDesc ?: "<none>");
		if (gDeniedTweaksDesc) free(gDeniedTweaksDesc);
	}
	if (gAllowedTweaks && gShouldLog && os_log_debug_enabled(OS_LOG_DEFAULT)) {
		char *gAllowedTweaksDesc = xpc_copy_description(gAllowedTweaks);
		os_log_dbg("Loaded allowed tweaks from environment: %{PUBLIC}s", gAllowedTweaksDesc ?: "<none>");
		if (gAllowedTweaksDesc) free(gAllowedTweaksDesc);
	}

	// Load preferences
	xpc_object_t preferencesXdict = xpc_object_from_plist(kChoicyPrefsPlistPath);
	if (preferencesXdict) {
		if (xpc_get_type(preferencesXdict) == XPC_TYPE_DICTIONARY) {
			xpc_object_t processPreferencesXdict = NULL;

			if (gBundleIdentifier) {
				xpc_object_t appPreferencesXdict = xpc_dictionary_get_value(preferencesXdict, kChoicyPrefsKeyAppSettings);
				if (appPreferencesXdict && xpc_get_type(appPreferencesXdict) == XPC_TYPE_DICTIONARY) {
					xpc_object_t thisAppXdict = xpc_dictionary_get_value(appPreferencesXdict, gBundleIdentifier);
					if (thisAppXdict && xpc_get_type(thisAppXdict) == XPC_TYPE_DICTIONARY) {
						processPreferencesXdict = thisAppXdict;
					}
				}
			}
			else {
				xpc_object_t daemonPreferencesXdict = xpc_dictionary_get_value(preferencesXdict, kChoicyPrefsKeyDaemonSettings);
				if (daemonPreferencesXdict && xpc_get_type(daemonPreferencesXdict) == XPC_TYPE_DICTIONARY) {
					const char *executableName = strrchr(gExecutablePath, '/');
					if (executableName) {
						xpc_object_t thisDaemonXdict = xpc_dictionary_get_value(daemonPreferencesXdict, &executableName[1]);
						if (thisDaemonXdict && xpc_get_type(thisDaemonXdict) == XPC_TYPE_DICTIONARY) {
							processPreferencesXdict = thisDaemonXdict;
						}
					}
				}
			}

			if (processPreferencesXdict && gShouldLog && os_log_debug_enabled(OS_LOG_DEFAULT)) {
				char *processPreferencesXdictDesc = xpc_copy_description(processPreferencesXdict);
				os_log_dbg("Loaded process preferences: %{PUBLIC}s", processPreferencesXdictDesc ?: "<none>");
				if (processPreferencesXdictDesc) free(processPreferencesXdictDesc);
			}

			// Load global preferences
			load_global_preferences(preferencesXdict, processPreferencesXdict);
			if (gGlobalDeniedTweaks && gShouldLog && os_log_debug_enabled(OS_LOG_DEFAULT)) {
				char *gGlobalDeniedTweaksDesc = xpc_copy_description(gGlobalDeniedTweaks);
				os_log_dbg("Loaded globally denied tweaks: %{PUBLIC}s", gGlobalDeniedTweaksDesc ?: "<none>");
				if (gGlobalDeniedTweaksDesc) free(gGlobalDeniedTweaksDesc);
			}

			// If neither the allow nor the deny list has been overwritten from the environment, load them from preferences
			if (!gDeniedTweaks && !gAllowedTweaks && processPreferencesXdict) {
				load_process_preferences(preferencesXdict, processPreferencesXdict);

				if (gDeniedTweaks && os_log_debug_enabled(OS_LOG_DEFAULT)) {
					char *gDeniedTweaksDesc = xpc_copy_description(gDeniedTweaks);
					os_log_dbg("Loaded denied tweaks from process preferences: %{PUBLIC}s", gDeniedTweaksDesc ?: "<none>");
					if (gDeniedTweaksDesc) free(gDeniedTweaksDesc);
				}
				if (gAllowedTweaks && os_log_debug_enabled(OS_LOG_DEFAULT)) {
					char *gAllowedTweaksDesc = xpc_copy_description(gAllowedTweaks);
					os_log_dbg("Loaded allowed tweaks from process preferences: %{PUBLIC}s", gAllowedTweaksDesc ?: "<none>");
					if (gAllowedTweaksDesc) free(gAllowedTweaksDesc);
				}
			}
		}
		xpc_release(preferencesXdict);
	}
	else if (gShouldLog) {
		os_log_err("Choicy failed to load preferences");
	}
}

bool dylib_is_tweak(const char *dylibPath)
{
	if (!dylibPath) return false;

	__block bool isTweak = false;
	if (path_is_probable_tweak(dylibPath)) {
		size_t dylibPathLength = strlen(dylibPath) + 1;
		char plistPath[dylibPathLength];
		strcpy(plistPath, dylibPath);
		strlcpy(&plistPath[dylibPathLength - 6], "plist", 6);

		if (access(plistPath, R_OK) == 0) {
			xpc_object_t tweakPlist = xpc_object_from_plist(plistPath);
			if (tweakPlist) {
				xpc_object_t filterXdict = xpc_dictionary_get_value(tweakPlist, "Filter");
				if (filterXdict && xpc_get_type(filterXdict) == XPC_TYPE_DICTIONARY) {
					xpc_dictionary_apply(filterXdict, ^bool(const char *key, xpc_object_t value) {
						if (value && xpc_get_type(value) == XPC_TYPE_ARRAY) {
							if (xpc_array_get_count(value) > 0) {
								isTweak = true;
								return false;
							}
						}
						return true;
					});
				}
				xpc_release(tweakPlist);
			}
		}
	}
	return isTweak;
}

bool should_load_dylib(const char *dylibPath)
{
	bool cachedDecision = false;
	if (dylib_decision_cache_get(dylibPath, &cachedDecision)) {
		return cachedDecision;
	}

	if(gTweakInjectionDisabled && string_has_suffix(dylibPath, "/usr/lib/ellekit/OldABI.dylib")) {
		dylib_decision_cache_set(dylibPath, false);
		return false;
	}

	if (!string_has_suffix(dylibPath, ".dylib")) {
		dylib_decision_cache_set(dylibPath, true);
		return true;
	}

	char *dylibNameHeap = path_copy_basename(dylibPath);
	char dylibName[strlen(dylibNameHeap)+1];
	strcpy(dylibName, dylibNameHeap);
	free(dylibNameHeap);

	dylibName[strlen(dylibName)-6] = '\0';

	if (!strcmp(dylibName, "   Choicy")) {
		dylib_decision_cache_set(dylibPath, true);
		return true;
	}

	os_log_dbg("Checking whether %{public}s.dylib should be loaded...", dylibName);

	bool pathLooksLikeTweak = path_is_probable_tweak(dylibPath);
	if (pathLooksLikeTweak && should_fast_block_all_tweaks()) {
		if (gProcessType == PROCESS_TYPE_APP) {
			if (!strcmp(gBundleIdentifier, kPreferencesBundleID)) {
				if (!strcmp(dylibName, "PreferenceLoader") || !strcmp(dylibName, "preferred")) {
					os_log_dbg("%{public}s.dylib ✅ (crucial)", dylibName);
					dylib_decision_cache_set(dylibPath, true);
					return true;
				}
			}
			else if (!strcmp(gBundleIdentifier, kSpringboardBundleID)) {
				if (!strcmp(dylibName, "ChoicySB")) {
					os_log_dbg("%{public}s.dylib ✅ (crucial)", dylibName);
					dylib_decision_cache_set(dylibPath, true);
					return true;
				}
			}
		}

		os_log_dbg("%{public}s.dylib ❌ (fast-blocked tweak in deny-all mode)", dylibName);
		dylib_decision_cache_set(dylibPath, false);
		return false;
	}

	if (pathLooksLikeTweak && gAllowedTweaks) {
		bool tweakIsAllowed = xpc_array_contains_string(gAllowedTweaks, dylibName);
		bool tweakIsGloballyDenied = xpc_array_contains_string(gGlobalDeniedTweaks, dylibName);

		if (tweakIsGloballyDenied) {
			os_log_dbg("%{public}s.dylib ❌ (disabled in global tweak configuration)", dylibName);
			dylib_decision_cache_set(dylibPath, false);
			return false;
		}

		if (!tweakIsAllowed) {
			os_log_dbg("%{public}s.dylib ❌ (fast-blocked tweak in allow mode)", dylibName);
			dylib_decision_cache_set(dylibPath, false);
			return false;
		}

		os_log_dbg("%{public}s.dylib ✅ (fast-allowed tweak in allow mode)", dylibName);
		dylib_decision_cache_set(dylibPath, true);
		return true;
	}

	if (dylib_is_tweak(dylibPath)) {
		// dylibs crucial for Choicy itself to work
		if (gProcessType == PROCESS_TYPE_APP) {
			if (!strcmp(gBundleIdentifier, kPreferencesBundleID)) {
				if (!strcmp(dylibName, "PreferenceLoader") || !strcmp(dylibName, "preferred")) {
					os_log_dbg("%{public}s.dylib ✅ (crucial)", dylibName);
					dylib_decision_cache_set(dylibPath, true);
					return true;
				}
			}
			else if (!strcmp(gBundleIdentifier, kSpringboardBundleID)) {
				if (!strcmp(dylibName, "ChoicySB")) {
					os_log_dbg("%{public}s.dylib ✅ (crucial)", dylibName);
					dylib_decision_cache_set(dylibPath, true);
					return true;
				}
			}
		}

		if (gTweakInjectionDisabled) {
			os_log_dbg("%{public}s.dylib ❌ (tweak injection disabled)", dylibName);
			dylib_decision_cache_set(dylibPath, false);
			return false;
		}

		bool tweakIsAllowed = xpc_array_contains_string(gAllowedTweaks, dylibName);
		bool tweakIsDenied = xpc_array_contains_string(gDeniedTweaks, dylibName);
		bool tweakIsGloballyDenied = xpc_array_contains_string(gGlobalDeniedTweaks, dylibName);

		if (tweakIsGloballyDenied) {
			os_log_dbg("%{public}s.dylib ❌ (disabled in global tweak configuration)", dylibName);
			dylib_decision_cache_set(dylibPath, false);
			return false;
		}

		if (gAllowedTweaks && !tweakIsAllowed) {
			os_log_dbg("%{public}s.dylib ❌ (custom tweak configuration on allow and tweak not allowed)", dylibName);
			dylib_decision_cache_set(dylibPath, false);
			return false;
		}

		if (gDeniedTweaks && tweakIsDenied) {
			os_log_dbg("%{public}s.dylib ❌ (custom tweak configuration on deny and tweak denied)", dylibName);
			dylib_decision_cache_set(dylibPath, false);
			return false;
		}
	}
	else {
		os_log_dbg("%{public}s.dylib ✅ (not a tweak)", dylibName);
		dylib_decision_cache_set(dylibPath, true);
		return true;
	}

	os_log_dbg("%{public}s.dylib ✅ (allowed)", dylibName);
	dylib_decision_cache_set(dylibPath, true);
	return true;
}

void *(*dlopen_from_orig)(const char*, int, void *) = NULL;
void *dlopen_from_hook(const char *path, int mode, void *lr)
{
	if (path) {
		if (!should_load_dylib(path)) {
			return NULL;
		}
	}
	return dlopen_from_orig(path, mode, lr);
}

void *(*dyld_dlopen_from_orig)(const void *, const char*, int, void *) = NULL;
void *dyld_dlopen_from_hook(const void *dyld, const char *path, int mode, void *lr)
{
	if (path) {
		if (!should_load_dylib(path)) {
			return NULL;
		}
	}
	return dyld_dlopen_from_orig(dyld, path, mode, lr);
}

const struct mach_header *find_tweak_loader_mach_header(const char **pathOut)
{
	const char *tweakLoaderPaths[] = {
		jbroot("/usr/lib/TweakLoader.dylib"),													 // Ellekit (Rootless Standard)
		jbroot("/usr/lib/substitute-loader.dylib"),											 // Substitute
		jbroot("/usr/lib/TweakInject.dylib"),													 // libhooker
		jbroot("/usr/lib/substrate/SubstrateLoader.dylib"),									 // Substrate
		jbroot("/Library/Frameworks/CydiaSubstrate.framework/Libraries/SubstrateLoader.dylib"), // Substrate (Older versions)
		jbroot("/usr/lib/Sonar/libsonar.dylib"),												 // Sonar
	};

	bool foundTweakLoader = false;
	struct stat tweakLoaderStat;
	for (int k = 0; k < sizeof(tweakLoaderPaths) / sizeof(*tweakLoaderPaths); k++) {
		if (access(tweakLoaderPaths[k], F_OK) == 0) {
			stat(tweakLoaderPaths[k], &tweakLoaderStat);
			foundTweakLoader = true;
			break;
		}
	}

	if (!foundTweakLoader) return NULL;

	for (int i = 0; i < _dyld_image_count(); i++) {
		const char *path = _dyld_get_image_name(i);
		struct stat pathStat;
		if (stat(path, &pathStat) == 0) {
			if (pathStat.st_dev == tweakLoaderStat.st_dev && pathStat.st_ino == tweakLoaderStat.st_ino) {
				os_log_dbg("Found tweak loader: %{public}s\n", path);
				if (pathOut) *pathOut = path;
				return _dyld_get_image_header(i);
			}
		}
	}

	return NULL;
}

int dyld_hook_routine(void **dyld, int idx, void *hook, void **orig, uint16_t pacSalt)
{
	if (!dyld) return -1;

	__unused uint64_t dyldPacDiversifier = ((uint64_t)dyld & ~(0xFFFFull << 48)) | (0x63FAull << 48);
	void **dyldFuncPtrs = ptrauth_auth_data(*dyld, ptrauth_key_process_independent_data, dyldPacDiversifier);
	if (!dyldFuncPtrs) return -1;

	if (vm_protect(mach_task_self_, (mach_vm_address_t)&dyldFuncPtrs[idx], sizeof(void *), false, VM_PROT_READ | VM_PROT_WRITE) == 0) {
	// on some devices vm_protect may fail due to (os/kern) protection failure in dsc::__DATA_CONST:__const when using in cache dyld
	} else if (vm_protect(mach_task_self_, (mach_vm_address_t)&dyldFuncPtrs[idx], sizeof(void *), false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) == 0) {
	} else {
		abort();
	}
	{
		uint64_t location = (uint64_t)&dyldFuncPtrs[idx];
		__unused uint64_t pacDiversifier = (location & ~(0xFFFFull << 48)) | ((uint64_t)pacSalt << 48);

		*orig = ptrauth_auth_and_resign(dyldFuncPtrs[idx], ptrauth_key_process_independent_code, pacDiversifier, ptrauth_key_function_pointer, 0);
		dyldFuncPtrs[idx] = ptrauth_auth_and_resign(hook, ptrauth_key_function_pointer, 0, ptrauth_key_process_independent_code, pacDiversifier);
		vm_protect(mach_task_self_, (mach_vm_address_t)&dyldFuncPtrs[idx], sizeof(void *), false, VM_PROT_READ);
		return 0;
	}

	return -1;
}

int replace_bss_pointers(const struct mach_header *mh, void *pointersToReplace[], void *replacementPointers[], uint32_t pointerCount)
{
	unsigned long bssSectionSize = 0;
	uint8_t *bssSection = getsectiondata((void *)mh, "__DATA", "__bss", &bssSectionSize);
	if (!bssSection) return 0;

	int replacementCount = 0;
	void **bssPtrs = (void **)bssSection;
	uint32_t bssPtrCount = (bssSectionSize / 8);
	for (uint32_t i = 0; i < bssPtrCount; i++) {
		void *curPtr = bssPtrs[i];
		for (uint32_t k = 0; k < pointerCount; k++) {
			if ((uintptr_t)curPtr == (uintptr_t)pointersToReplace[k]) {
				bssPtrs[i] = replacementPointers[k];
				replacementCount++;
			}
		}
	}
	return replacementCount;
}

__attribute__((constructor)) static void initializer(void)
{
	load_process_info();
	os_log_dbg("Choicy loaded");
	scrub_stealth_environment();

	if (gTweakInjectionDisabled || gAllowedTweaks || gDeniedTweaks || gGlobalDeniedTweaks) {
		os_log_dbg("Initializing Choicy...");

		void **dyld4Struct = litehook_find_dsc_symbol("/usr/lib/system/libdyld.dylib", "__ZN5dyld45gDyldE");
		if (dyld4Struct) {
			// iOS 15+
			// dyld_dynamic_interpose is a stub, so apply the hooks by overwriting function pointers in gDyld
			// This will catch *all* dlopen calls

			dyld_hook_routine(*dyld4Struct, 14, (void *)&dyld_dlopen_hook, (void **)&dyld_dlopen_orig, 0xBF31);
			dyld_hook_routine(*dyld4Struct, 97, (void *)&dyld_dlopen_from_hook, (void **)&dyld_dlopen_from_orig, 0xD48C);
		}
		else {
			// iOS <=14
			// gDyld does not exist yet, but dyld_dynamic_interpose still works, so use that
			// This will only catch dlopen calls originating from the tweak loader

			void *libdyldHandle = dlopen("/usr/lib/system/libdyld.dylib", RTLD_NOW);
			void *dlopen_from = dlsym(libdyldHandle, "dlopen_from");

			dlopen_orig = dlopen;
			if (dlopen_from) dlopen_from_orig = dlopen_from;

			const char *tweakLoaderPath = NULL;
			const struct mach_header *tweakLoaderHeader = find_tweak_loader_mach_header(&tweakLoaderPath);
			if (tweakLoaderHeader) {
				bool skipDynamicInterpose = false;

				// On rootful / iOS <=14, there are multiple different special cases we need to take care of
				// First: substitute-loader.dylib is heavily obfuscated and gets the dlopen pointer via dlsym before Choicy runs
				// So in order to support substitute, we have to find the dlopen pointer in it's BSS section and replace it
				if (!strcmp(tweakLoaderPath, "/usr/lib/substitute-loader.dylib")) {
					void *pointersToReplace[] = {
						dlopen,
						dlopen_from,
					};

					void *replacementPointers[] = {
						dlopen_hook,
						dlopen_from_hook,
					};

					uint32_t pointerCount = sizeof(pointersToReplace) / sizeof(*pointersToReplace);
					if (!dlopen_from) pointerCount--;
					__unused int c = replace_bss_pointers(tweakLoaderHeader, pointersToReplace, replacementPointers, pointerCount);
					os_log_dbg("Replaced %u dlopen/dlopen_from pointer(s) in bss section", c);

					// Fall through, since older versions of substitute-loader still called dlopen normally and we don't know what we're dealing with
				}
#ifdef __arm64e__
				// Second: dyld_dynamic_interpose seems to cause a nullptr deref in arm64e processes
				// So, we have to use a litehook rebind instead
				litehook_rebind_symbol((const mach_header *)tweakLoaderHeader, dlopen, dlopen_hook);
				if (dlopen_from) {
					litehook_rebind_symbol((const mach_header *)tweakLoaderHeader, dlopen_from, dlopen_from_hook);
				}
				skipDynamicInterpose = true;
#endif
				// If not arm64e, we can just use dyld_dynamic_interpose, which (unlike litehook) supports armv7 aswell
				if (!skipDynamicInterpose) {
					static struct dyld_interpose_tuple interposes[2];
					interposes[0] = (struct dyld_interpose_tuple){ .replacement = dlopen_hook, .replacee = dlopen };
					if (dlopen_from) {
						interposes[1] = (struct dyld_interpose_tuple){ .replacement = dlopen_from_hook, .replacee = dlopen_from };
					}
					dyld_dynamic_interpose(tweakLoaderHeader, interposes, dlopen_from ? 2 : 1);
					os_log_dbg("Initialized %u interpose(s) in tweak loader", dlopen_from ? 2 : 1);
				}
			}
			else {
				os_log_dbg("Unable to find tweak loader");
			}
		}
	}
	if (should_enable_stealth_hiding()) {
		install_stealth_hiding_hooks();
	}
}
