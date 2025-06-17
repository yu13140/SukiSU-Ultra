#ifndef ___ZAKO_API_H
#define ___ZAKO_API_H

#include "ksu.h"

int zako_handle_api(unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
int zako_is_api_control_code(unsigned long arg2);

#define CMD_ZAKO 100
#define CMD_ZAKO_MAX 103

#define CMD_ENABLE_KPM 100
#define CMD_HOOK_TYPE 101
#define CMD_GET_SUSFS_FEATURE_STATUS 102

// SUSFS Functional State Structures
struct susfs_feature_status {
	bool status_sus_path;
	bool status_sus_mount;
	bool status_auto_default_mount;
	bool status_auto_bind_mount;
	bool status_sus_kstat;
	bool status_try_umount;
	bool status_auto_try_umount_bind;
	bool status_spoof_uname;
	bool status_enable_log;
	bool status_hide_symbols;
	bool status_spoof_cmdline;
	bool status_open_redirect;
	bool status_magic_mount;
	bool status_overlayfs_auto_kstat;
	bool status_sus_su;
};

void zako_check_kpm_enabled(void __user *result);
void zako_get_hook_type(void __user *result, void __user *reply_ok);
void zako_get_susfs_feature_status(void __user *result, void __user *reply_ok);

#endif