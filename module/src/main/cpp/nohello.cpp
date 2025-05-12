/* Copyright 2022-2023 John "topjohnwu" Wu
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>
#include <filesystem>

#include "zygisk.hpp"
#include "external/android_filesystem_config.h"
#include "mountsinfo.cpp"
#include "utils.cpp"
#include "external/fdutils/fd_utils.cpp"
#include <sys/mount.h>
#include <endian.h>
#include <thread>
#include "log.h"
#include "PropertyManager.cpp"
#include "external/emoji.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

namespace fs = std::filesystem;

static constexpr off_t EXT_SUPERBLOCK_OFFSET = 0x400;
static constexpr off_t EXT_MAGIC_OFFSET = 0x38;
static constexpr off_t EXT_ERRORS_OFFSET = 0x3C;
static constexpr uint16_t EXT_MAGIC = 0xEF53;

#define MODULE_CONFLICT  2

static const std::set<std::string> toumount = {"KSU", "APatch", "magisk", "worker"};


static bool anomaly(MountRootResolver mrs, const MountInfo &mount) {
	if (mrs.resolveRoot(mount).starts_with("/data/adb") || mount.getMountPoint().starts_with("/data/adb")) {
		return true;
	}
	const auto& fs = mount.getFsType();
	if (fs == "overlay" || fs == "tmpfs") {
		if (toumount.contains(mount.getMountSource())) {
			return true;
		}
	}
	if (fs == "overlay") {
		const auto& fm = mount.getMountOptions().flagmap;
		if (fm.contains("lowerdir") && fm.at("lowerdir").starts_with("/data/adb")) {
			return true;
		}
		if (fm.contains("upperdir") && fm.at("upperdir").starts_with("/data/adb")) {
			return true;
		}
		if (fm.contains("workdir") && fm.at("workdir").starts_with("/data/adb")) {
			return true;
		}
	}
	return false;
}


static std::unique_ptr<std::string> getExternalErrorBehaviour(const MountInfo& mount) {
	const auto& fs = mount.getFsType();
	if (fs != "ext2" && fs != "ext3" && fs != "ext4")
		return nullptr;
	std::ifstream mntsrc(mount.getMountSource(), std::ios::binary);
	if (!mntsrc || !mntsrc.is_open())
		return nullptr;
	uint16_t magic;
	mntsrc.seekg(EXT_SUPERBLOCK_OFFSET + EXT_MAGIC_OFFSET, std::ios::beg);
	mntsrc.read(reinterpret_cast<char *>(&magic), sizeof(magic));
	if (!mntsrc || mntsrc.gcount() != sizeof(magic))
		return nullptr;
	magic = le16toh(magic);
	if (magic != EXT_MAGIC)
		return nullptr;
	uint16_t errors;
	mntsrc.seekg(EXT_SUPERBLOCK_OFFSET + EXT_ERRORS_OFFSET, std::ios::beg);
	mntsrc.read(reinterpret_cast<char *>(&errors), sizeof(errors));
	if (!mntsrc || mntsrc.gcount() != sizeof(errors))
		return nullptr;
	errors = le16toh(errors);
	switch (errors)
	{
		case 1:
			return std::make_unique<std::string>("continue");
		case 2:
			return std::make_unique<std::string>("remount-ro");
		case 3:
			return std::make_unique<std::string>("panic");
		default:
			return nullptr;
	}
	return nullptr;
}

static void unmount(const std::vector<MountInfo>& mounts) {
	MountRootResolver mrs(mounts);
	for (auto mount = mounts.rbegin(); mount != mounts.rend(); mount++) {
		if (anomaly(mrs, *mount)) {
			errno = 0;
			int res;
			if ((res = umount2(mount->getMountPoint().c_str(), MNT_DETACH)) == 0)
				LOGD("umount2(\"%s\", MNT_DETACH): returned (0): 0 (Success)", mount->getMountPoint().c_str());
			else
				LOGE("umount2(\"%s\", MNT_DETACH): returned %d: %d (%s)", mount->getMountPoint().c_str(), res, errno, strerror(errno));
		}
	}
}

static void remount(const std::vector<MountInfo>& mounts) {
	for (const auto& mount : mounts) {
		if (mount.getMountPoint() == "/data") {
			const auto& mntopts = mount.getMountOptions();
			const auto& fm = mntopts.flagmap;
			if (!fm.contains("errors"))
				break;
			auto errors = getExternalErrorBehaviour(mount);
			if (!errors || fm.at("errors") == *errors)
				break;
			auto mntflags = mount.getFlags();
			unsigned int flags = MS_REMOUNT;
			if (mntflags & MountFlags::NOSUID) {
				flags |= MS_NOSUID;
			}
			if (mntflags & MountFlags::NODEV) {
				flags |= MS_NODEV;
			}
			if (mntflags & MountFlags::NOEXEC) {
				flags |= MS_NOEXEC;
			}
			if (mntflags & MountFlags::NOATIME) {
				flags |= MS_NOATIME;
			}
			if (mntflags & MountFlags::NODIRATIME) {
				flags |= MS_NODIRATIME;
			}
			if (mntflags & MountFlags::RELATIME) {
				flags |= MS_RELATIME;
			}
			if (mntflags & MountFlags::NOSYMFOLLOW) {
				flags |= MS_NOSYMFOLLOW;
			}
			int res;
			if ((res = ::mount(nullptr, "/data", nullptr, flags, (std::string("errors=") + *errors).c_str())) == 0)
				LOGD("mount(nullptr, \"/data\", nullptr, 0x%x, \"errors=%s\"): returned (0): 0 (Success)", flags, errors->c_str());
			else
				LOGW("mount(NULL, \"/data\", NULL, 0x%x, \"errors=%s\"): returned %d: %d (%s)", flags, errors->c_str(), res, errno, strerror(errno));
			break;
		}
	}
}

static std::function<void()> nocb = []() {};

int (*ar_unshare)(int) = nullptr;
int (*ar_setresuid)(uid_t, uid_t, uid_t) = nullptr;

static int reshare(int flags) {
	nocb();
	errno = 0;
	return flags == CLONE_NEWNS ? 0 : ar_unshare(flags & ~CLONE_NEWNS);
}

static int resetresuid(uid_t ruid, uid_t euid, uid_t suid) {
	nocb();
	return ar_setresuid(ruid, euid, suid);
}



class NoHello : public zygisk::ModuleBase {
public:
    void onLoad(Api *_api, JNIEnv *_env) override {
        this->api = _api;
        this->env = _env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        // Use JNI to fetch our process name
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        preSpecialize(process);
        env->ReleaseStringUTFChars(args->nice_name, process);
    }

	void postAppSpecialize(const AppSpecializeArgs *args) override {
		const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
		postSpecialize(process);
		env->ReleaseStringUTFChars(args->nice_name, process);
	}

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        //preSpecialize("system_server");
		api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api{};
    JNIEnv *env{};
	dev_t dev{};
	ino_t inode{};

    void preSpecialize(const char *process) {
        // Demonstrate connecting to to companion process
        // We ask the companion for a random number
		unsigned int flags = api->getFlags();
		if (flags & zygisk::StateFlag::PROCESS_GRANTED_ROOT) {
			api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
			return;
		}
		if (flags & zygisk::StateFlag::PROCESS_ON_DENYLIST) {
			pid_t pid = getpid();
			int fd = api->connectCompanion();
			api->exemptFd(fd);
			std::tie(dev, inode) = devinoby("libandroid_runtime.so");
			api->pltHookRegister(dev, inode, "unshare", (void*) reshare, (void**) &ar_unshare);
			api->pltHookRegister(dev, inode, "setresuid", (void*) resetresuid, (void**) &ar_setresuid);
			api->pltHookCommit();
			nocb = [pid, cfd = fd]() {
				nocb = []() {};
				std::vector<std::unique_ptr<FileDescriptorInfo>> fdivec;
				/*auto fds = GetOpenFds([](const std::string &error){
					LOGE("[zygisk::PreSpecialize] GetOpenFds: %s", error.c_str());
				});
				for (auto &fd : *fds) {
					auto fdi = FileDescriptorInfo::CreateFromFd(fd, [fd](const std::string &error){
						LOGE("[zygisk::PreSpecialize] CreateFromFd(%d): %s", fd, error.c_str());
					});
					if (fdi && !fdi->is_sock && !fdi->file_path.starts_with("/memfd:"))
						fdivec.emplace_back(std::move(fdi));
				}*/
				int res = ar_unshare(CLONE_NEWNS);
				if (res != 0) {
					LOGE("[zygisk::PreSpecialize] ar_unshare: %s", strerror(errno));
					return;
				}
				res = mount("rootfs", "/", nullptr, MS_SLAVE | MS_REC, nullptr);
				if (res != 0) {
					LOGE("[zygisk::PreSpecialize] mount: %s", strerror(errno));
					return;
				}
				if (write(cfd, &pid, sizeof(pid)) != sizeof(pid)) {
					LOGE("[zygisk::PreSpecialize] write: %s", strerror(errno));
					return;
				}
				if (read(cfd, &res, sizeof(res)) != sizeof(res)) {
					LOGE("[zygisk::PreSpecialize] read: %s", strerror(errno));
					return;
				}
				close(cfd);
				if (res == MODULE_CONFLICT) {
					mount(nullptr, "/", nullptr, MS_SHARED | MS_REC, nullptr);
					return;
				} else if (res == EXIT_FAILURE) {
					LOGW("[zygisk::PreSpecialize]: Fallback to unmount in zygote process");
					unmount(getMountInfo());
				}
				/*for (auto &fdi : fdivec) {
					//LOGD("Reopening FD %d with %s", fdi->fd, fdi->file_path.c_str());
					fdi->ReopenOrDetach([fd = fdi->fd](const std::string &error){
						LOGE("[zygisk::PreSpecialize] ReopenOrDetach(%d): %s", fd, error.c_str());
					});
				}*/
			};
			return;
		}
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

	void postSpecialize(const char *process) {
		if (ar_unshare)
			api->pltHookRegister(dev, inode, "unshare", (void*) ar_unshare, nullptr);
		if (ar_setresuid)
			api->pltHookRegister(dev, inode, "setresuid", (void*) ar_setresuid, nullptr);
		api->pltHookCommit();
		api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
	}

};

static void NoRoot(int fd) {
	pid_t pid = -1;
	static unsigned int sucrate = 0;
	static const std::string description = [] {
		std::ifstream f("/data/adb/modules/zygisk_nohello/description");
		return f ? std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>()) : "A Zygisk module to hide root.";
	}();
	static const bool compatbility = [] {
		if (fs::exists("/data/adb/modules/zygisk_shamiko") && !fs::exists("/data/adb/modules/zygisk_shamiko/disable"))
			return false;
		if (fs::exists("/data/adb/modules/zygisk-assistant") && !fs::exists("/data/adb/modules/zygisk-assistant/disable"))
			return false;
		return true;
	}();
	int result;
	if (read(fd, &pid, sizeof(pid)) != sizeof(pid)) {
		close(fd);
		return;
	}
	PropertyManager pm("/data/adb/modules/zygisk_nohello/module.prop");
	if (!compatbility) {
		result = MODULE_CONFLICT;
		pm.setProp("description", "[" + emoji::emojize(":x: ") + "Incompatible environment] " + description);
		goto skip;
	}
	result = forkcall(
		[pid]()
		{
			int res = switchnsto(pid);
			if (!res) {
				LOGE("[ps::Companion] setns: %s", strerror(errno));
				return EXIT_FAILURE;
			}
			auto mounts = getMountInfo();
			unmount(mounts);
			remount(mounts);
			return EXIT_SUCCESS;
		}
	);
	if (result == EXIT_SUCCESS) {
		sucrate++;
		pm.setProp("description", "[" + emoji::emojize(":yum: ") + "Nohello unmounted (" + std::to_string(sucrate) + ") time(s)] " + description);
	}
	skip:
	if (write(fd, &result, sizeof(result)) != sizeof(result)) {
		LOGE("[ps::Companion] write: %s", strerror(errno));
	}
	close(fd);
}

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(NoHello)
REGISTER_ZYGISK_COMPANION(NoRoot)
