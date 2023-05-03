#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(.gnu.linkonce.this_module) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section(__versions) = {
	{ 0xb3753869, "module_layout" },
	{ 0xb0ebce5e, "param_ops_long" },
	{ 0xe007de41, "kallsyms_lookup_name" },
	{ 0xc5850110, "printk" },
	{ 0x8b9200fd, "lookup_address" },
	{ 0x754d539c, "strlen" },
	{ 0x349cba85, "strchr" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x1b44c663, "current_task" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0x7aa1756e, "kvfree" },
	{ 0xb44ad4b3, "_copy_to_user" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0xa916b694, "strnlen" },
	{ 0x599fb41c, "kvmalloc_node" },
	{ 0xdecd0b29, "__stack_chk_fail" },
	{ 0xb0e602eb, "memmove" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x3c3ff9fd, "sprintf" },
	{ 0x2ea2c95c, "__x86_indirect_thunk_rax" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "F5931EB9380FA23976B3F0E");
