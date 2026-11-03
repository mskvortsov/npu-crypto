include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=airoha-npu-crypto
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define KernelPackage/airoha-npu-crypto
  SUBMENU:=Cryptographic API modules
  TITLE:=Experimental AN7581 NPU crypto offload
  DEPENDS:=@TARGET_airoha_an7581
  KCONFIG:=CONFIG_CRYPTO_DEV_AIROHA_NPU=y CONFIG_CRYPTO_ENGINE=y
  FILES:=$(PKG_BUILD_DIR)/linux/airoha_npu_crypto.ko
  AUTOLOAD:=$(call AutoLoad,50,airoha_npu_crypto)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/. $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) -f npu/firmware.mk
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)/linux" modules
endef

define KernelPackage/airoha-npu-crypto/install
	$(INSTALL_DIR) $(1)/lib/firmware/airoha
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/build/AN7581_CRYPTO/npu_rv32.bin $(1)/lib/firmware/airoha/an7581_crypto.bin
	$(INSTALL_DIR) $(1)/usr/share/licenses/airoha-npu-crypto
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/npu/cryptogams/LICENSE $(1)/usr/share/licenses/airoha-npu-crypto/cryptogams
endef

$(eval $(call KernelPackage,airoha-npu-crypto))
