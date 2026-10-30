// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

pub const xex_magic = [_]u8{ 'X', 'E', 'X', '2' };

pub const module_flag_title_module: u32 = 0x00000001;
pub const module_flag_exports_to_title: u32 = 0x00000002;
pub const module_flag_system_debugger: u32 = 0x00000004;
pub const module_flag_dll_module: u32 = 0x00000008;
pub const module_flag_patch_module: u32 = 0x00000010;
pub const module_flag_patch_full: u32 = 0x00000020;
pub const module_flag_patch_delta: u32 = 0x00000040;
pub const module_flag_user_mode: u32 = 0x00000080;
pub const module_flag_unknown: u32 = 0xFFFFFF00;

pub const image_flag_manufacturing_utility: u32 = 0x00000002;
pub const image_flag_manufacturing_tool: u32 = 0x00000004;
pub const image_flag_xgd2: u32 = 0x00000008;
pub const image_flag_cardea_key: u32 = 0x00000100;
pub const image_flag_xeika_key: u32 = 0x00000200;
pub const image_flag_title_usermode: u32 = 0x00000400;
pub const image_flag_system_usermode: u32 = 0x00000800;
pub const image_flag_orange0: u32 = 0x00001000;
pub const image_flag_orange1: u32 = 0x00002000;
pub const image_flag_orange2: u32 = 0x00004000;
pub const image_flag_signed_kv_restricted: u32 = 0x00008000;
pub const image_flag_iptv_signup_app: u32 = 0x00010000;
pub const image_flag_iptv_title_app: u32 = 0x00020000;
pub const image_flag_nccp_keys: u32 = 0x00040000;
pub const image_flag_activation_req: u32 = 0x08000000;
pub const image_flag_4k_pages: u32 = 0x10000000;
pub const image_flag_no_game_region: u32 = 0x20000000;
pub const image_flag_revocation_check_opt: u32 = 0x40000000;
pub const image_flag_revocation_check_req: u32 = 0x80000000;
pub const image_flag_unknown: u32 = 0x07F800F1;

pub const region_north_america: u32 = 0x000000FF;
pub const region_japan: u32 = 0x00000100;
pub const region_china: u32 = 0x00000200;
pub const region_rest_of_asia: u32 = 0x0000FC00;
pub const region_aust_nz: u32 = 0x00010000;
pub const region_rest_of_europe: u32 = 0x00FE0000;
pub const region_rest_of_world: u32 = 0xFF000000;
pub const region_all: u32 = 0xFFFFFFFF;

pub const media_hard_disk: u32 = 0x00000001;
pub const media_dvdx2: u32 = 0x00000002;
pub const media_dvd_cd: u32 = 0x00000004;
pub const media_dvd5: u32 = 0x00000008;
pub const media_dvd9: u32 = 0x00000010;
pub const media_sys_flash: u32 = 0x00000020;
pub const media_mem_unit: u32 = 0x00000080;
pub const media_mass_storage: u32 = 0x00000100;
pub const media_smb: u32 = 0x00000200;
pub const media_ram: u32 = 0x00000400;
pub const media_ram_drive: u32 = 0x00000800;
pub const media_secure_virt_od: u32 = 0x00001000;
pub const media_wireless_n_storage: u32 = 0x00002000;
pub const media_sys_ext_partition: u32 = 0x00004000;
pub const media_sys_aux_partition: u32 = 0x00008000;
pub const media_insecure_pkg: u32 = 0x01000000;
pub const media_savegame_pkg: u32 = 0x02000000;
pub const media_localsign_pkg: u32 = 0x04000000;
pub const media_livesign_pkg: u32 = 0x08000000;
pub const media_xbox_pkg: u32 = 0x10000000;
pub const media_unknown: u32 = 0xE0FF0040;
pub const media_all: u32 = 0xFFFFFFFF;

pub const section_info_unused0: u8 = 0;
pub const section_info_code: u8 = 1;
pub const section_info_data: u8 = 2;
pub const section_info_readonly: u8 = 3;
pub const section_info_unused4: u8 = 4;

pub const sys_flag_unknown: u32 = 0x00000000;
pub const sys_flag_no_force_reboot: u32 = 0x00000001;
pub const sys_flag_foreground_tasks: u32 = 0x00000002;
pub const sys_flag_no_odd_mapping: u32 = 0x00000004;
pub const sys_flag_handle_mce_input: u32 = 0x00000008;
pub const sys_flag_restrict_hud_features: u32 = 0x00000010;
pub const sys_flag_handle_gamepad_disconnect: u32 = 0x00000020;
pub const sys_flag_insecure_sockets: u32 = 0x00000040;
pub const sys_flag_xbox1_xsp_interop: u32 = 0x00000080;
pub const sys_flag_set_dash_context: u32 = 0x00000100;
pub const sys_flag_uses_game_voice_channel: u32 = 0x00000200;
pub const sys_flag_pal50_incompatible: u32 = 0x00000400;
pub const sys_flag_insecure_utilitydrive: u32 = 0x00000800;
pub const sys_flag_has_xam_hooks: u32 = 0x00001000;
pub const sys_flag_pii: u32 = 0x00002000;
pub const sys_flag_crossplatform_syslink: u32 = 0x00004000;
pub const sys_flag_multidisc_swap: u32 = 0x00008000;
pub const sys_flag_multidisc_insecure_media: u32 = 0x00010000;
pub const sys_flag_ap25_media: u32 = 0x00020000;
pub const sys_flag_no_confirm_exit: u32 = 0x00040000;
pub const sys_flag_allow_bkgrnd_download: u32 = 0x00080000;
pub const sys_flag_create_persist_ramdrive: u32 = 0x00100000;
pub const sys_flag_inherit_persist_ramdrive: u32 = 0x00200000;
pub const sys_flag_allow_hud_vibration: u32 = 0x00400000;
pub const sys_flag_both_utility_partitions: u32 = 0x00800000;
pub const sys_flag_handle_iptv_input: u32 = 0x01000000;
pub const sys_flag_prefer_bigbutton_input: u32 = 0x02000000;
pub const sys_flag_allow_xsam_reservation: u32 = 0x04000000;
pub const sys_flag_multidisc_cross_title: u32 = 0x08000000;
pub const sys_flag_title_install_incompatible: u32 = 0x10000000;
pub const sys_flag_allow_avatar_get_metadata: u32 = 0x20000000;
pub const sys_flag_allow_controller_swapping: u32 = 0x40000000;
pub const sys_flag_dash_extensibility_module: u32 = 0x80000000;

pub const sys_flag2_allow_network_read_cancel: u32 = 0x00000001;
pub const sys_flag2_uninterruptable_reads: u32 = 0x00000002;
pub const sys_flag2_require_full_experience: u32 = 0x00000004;
pub const sys_flag2_gamevoice_required_ui: u32 = 0x00000008;
pub const sys_flag2_title_set_presence_string: u32 = 0x00000010;
pub const sys_flag2_natal_tiltcontrol: u32 = 0x00000020;
pub const sys_flag2_requires_skeletal_tracking: u32 = 0x00000040;
pub const sys_flag2_supports_skeletal_tracking: u32 = 0x00000080;
pub const sys_flag2_use_large_hds_file_cache: u32 = 0x00000100;
pub const sys_flag2_title_supports_deep_link: u32 = 0x00000200;
pub const sys_flag2_unknown: u32 = 0xFFFFFC00;

pub const image_key_resource_section: u32 = 0x000002FF;
pub const image_key_basefile_format: u32 = 0x000003FF;
pub const image_key_base_reference: u32 = 0x00000405;
pub const image_key_delta_patch_descriptor: u32 = 0x000005FF;
pub const image_key_restrict_kv_privs: u32 = 0x00004004;
pub const image_key_restrict_dates: u32 = 0x00004104;
pub const image_key_restrict_console_ids: u32 = 0x000042FF;
pub const image_key_disc_profile_id: u32 = 0x00004304;
pub const image_key_bound_pathname: u32 = 0x000080FF;
pub const image_key_bound_device_id: u32 = 0x00008105;
pub const image_key_original_base_address: u32 = 0x00010001;
pub const image_key_entry_point: u32 = 0x00010100;
pub const image_key_image_base_address: u32 = 0x00010201;
pub const image_key_import_libraries: u32 = 0x000103FF;
pub const image_key_image_checksum: u32 = 0x00018002;
pub const image_key_image_callcap: u32 = 0x00018102;
pub const image_key_image_fastcap: u32 = 0x00018200;
pub const image_key_original_pe_name: u32 = 0x000183FF;
pub const image_key_library_versions: u32 = 0x000200FF;
pub const image_key_tls_values: u32 = 0x00020104;
pub const image_key_stack_size: u32 = 0x00020200;
pub const image_key_filesystem_cache_size: u32 = 0x00020301;
pub const image_key_heap_size: u32 = 0x00020401;
pub const image_key_page_heap: u32 = 0x00028002;
pub const image_key_system_flags: u32 = 0x00030000;
pub const image_key_system_flags2: u32 = 0x00030100;
pub const image_key_execution_id: u32 = 0x00040006;
pub const image_key_title_workspace_size: u32 = 0x00040201;
pub const image_key_game_ratings: u32 = 0x00040310;
pub const image_key_lan_key: u32 = 0x00040404;
pub const image_key_logo_data: u32 = 0x000405FF;
pub const image_key_multidisc_media_ids: u32 = 0x000406FF;
pub const image_key_alt_title_ids: u32 = 0x000407FF;
pub const image_key_extra_debug_memory: u32 = 0x00040801;
pub const image_key_exports_by_name: u32 = 0x00E10402;

pub fn isDataOffset(key: u32) bool {
    return (key & 0xFF) != 0x00 and (key & 0xFF) != 0x01;
}

pub fn isVariableSize(key: u32) bool {
    return (key & 0xFF) == 0xFF;
}

pub fn headerSizeFor(key: u32) u32 {
    return (key & 0xFF) * 4;
}
