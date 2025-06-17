#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include "zako_api.h"


#ifndef NO_OPTIMIZE
#if defined(__GNUC__) && !defined(__clang__)
    #define NO_OPTIMIZE __attribute__((optimize("O0")))
#elif defined(__clang__)
    #define NO_OPTIMIZE __attribute__((optnone))
#else
    #define NO_OPTIMIZE
#endif
#endif

// ============================================================================================


// Check if kpm is enabled
noinline
NO_OPTIMIZE
void zako_check_kpm_enabled(void __user *result)
{
	bool KPM_Enabled = IS_ENABLED(CONFIG_KPM);
	
	if (copy_to_user(result, &KPM_Enabled, sizeof(KPM_Enabled))) {
		pr_err("zako_api: KPM check copy_to_user() failed\n");
		return;
	}
	
	pr_info("zako_api: KPM enabled status checked: %s\n", KPM_Enabled ? "true" : "false");
}

// Checking hook usage
noinline
NO_OPTIMIZE
void zako_get_hook_type(void __user *result, void __user *reply_ok)
{
	const char *hook_type;
	u32 reply_ok_val = KERNEL_SU_OPTION;
	
#ifdef CONFIG_KSU_MANUAL_HOOK
	hook_type = "Manual";
#elif defined(CONFIG_KSU_KPROBES_HOOK)
	hook_type = "Kprobes";
#else
	hook_type = "Unknown";
#endif
	
	size_t len = strlen(hook_type) + 1;
	if (copy_to_user(result, hook_type, len)) {
		pr_err("zako_api: hook_type copy_to_user failed\n");
		return;
	}
	
	if (copy_to_user(reply_ok, &reply_ok_val, sizeof(reply_ok_val))) {
		pr_err("zako_api: hook_type reply error\n");
		return;
	}
	
	pr_info("zako_api: Hook type returned: %s\n", hook_type);
}

// Get SUSFS function status
noinline
NO_OPTIMIZE
void zako_get_susfs_feature_status(void __user *result, void __user *reply_ok)
{
	struct susfs_feature_status status;
	u32 reply_ok_val = KERNEL_SU_OPTION;
	
	memset(&status, 0, sizeof(status));
	
	if (!ksu_access_ok(result, sizeof(status))) {
		pr_err("zako_api: susfs_feature_status result is not accessible\n");
		return;
	}
	
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	status.status_sus_path = true;
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	status.status_sus_mount = true;
#endif

#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
	status.status_auto_default_mount = true;
#endif

#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
	status.status_auto_bind_mount = true;
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	status.status_sus_kstat = true;
#endif

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	status.status_try_umount = true;
#endif

#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
	status.status_auto_try_umount_bind = true;
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	status.status_spoof_uname = true;
#endif

#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	status.status_enable_log = true;
#endif

#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
	status.status_hide_symbols = true;
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	status.status_spoof_cmdline = true;
#endif

#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	status.status_open_redirect = true;
#endif

#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
	status.status_magic_mount = true;
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_OVERLAYFS
	status.status_overlayfs_auto_kstat = true;
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_SU
	status.status_sus_su = true;
#endif

	if (copy_to_user(result, &status, sizeof(status))) {
		pr_err("zako_api: susfs_feature_status copy_to_user failed\n");
		return;
	}
	
	if (copy_to_user(reply_ok, &reply_ok_val, sizeof(reply_ok_val))) {
		pr_err("zako_api: susfs_feature_status reply error\n");
		return;
	}
	
	pr_info("zako_api: SUSFS feature status successfully returned\n");
}

noinline
int zako_handle_api(unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	pr_info("zako_api: handling command %lu\n", arg2);
	
	switch (arg2) {
	case CMD_ENABLE_KPM:
		zako_check_kpm_enabled((void __user *)arg3);
		break;
		
	case CMD_HOOK_TYPE:
		zako_get_hook_type((void __user *)arg3, (void __user *)arg5);
		break;
		
	case CMD_GET_SUSFS_FEATURE_STATUS:
		zako_get_susfs_feature_status((void __user *)arg3, (void __user *)arg5);
		break;
		
	default:
		pr_warn("zako_api: unknown command: %lu\n", arg2);
		return -EINVAL;
	}
	
	return 0;
}

int zako_is_api_control_code(unsigned long arg2)
{
	return (arg2 >= CMD_ZAKO && arg2 <= CMD_ZAKO_MAX) ? 1 : 0;
}