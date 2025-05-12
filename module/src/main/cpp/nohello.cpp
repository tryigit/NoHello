/* Copyright 2022-2023 John "topjohnwu" Wu
 * Copyright 2024 The NoHello Contributors
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
#include <vector>
#include <utility> // For std::pair, std::move

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

static const std::set<std::string> toumount_sources = {"KSU", "APatch", "magisk", "worker"};
static const std::string adb_path_prefix = "/data/adb";

static bool anomaly(MountRootResolver mrs, const MountInfo &mount) {
	const std::string resolved_root = mrs.resolveRoot(mount);
	if (resolved_root.starts_with(adb_path_prefix) || mount.getMountPoint().starts_with(adb_path_prefix)) {
		return true;
	}

	const auto& fs_type = mount.getFsType();
	const auto& mnt_src = mount.getMountSource();

	if (toumount_sources.count(mnt_src)) { // Use .count for std::set
		return true;
	}

	if (fs_type == "overlay") {
		if (toumount_sources.count(mnt_src)) {
			return true;
		}
		const auto& fm = mount.getMountOptions().flagmap;
		if (fm.count("lowerdir") && fm.at("lowerdir").starts_with(adb_path_prefix)) {
			return true;
		}
		if (fm.count("upperdir") && fm.at("upperdir").starts_with(adb_path_prefix)) {
			return true;
		}
		if (fm.count("workdir") && fm.at("workdir").starts_with(adb_path_prefix)) {
			return true;
		}
	} else if (fs_type == "tmpfs") {
		if (toumount_sources.count(mnt_src)) {
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
	for (auto mount_it = mounts.rbegin(); mount_it != mounts.rend(); ++mount_it) {
        const auto& mount = *mount_it;
		if (anomaly(mrs, mount)) {
			errno = 0;
			int res;
			if ((res = umount2(mount.getMountPoint().c_str(), MNT_DETACH)) == 0)
				LOGD("umount2(\"%s\", MNT_DETACH): returned (0): 0 (Success)", mount.getMountPoint().c_str());
			else
				LOGE("umount2(\"%s\", MNT_DETACH): returned %d: %d (%s)", mount.getMountPoint().c_str(), res, errno, strerror(errno));
		}
	}
}

static void remount(const std::vector<MountInfo>& mounts) {
	for (const auto& mount : mounts) {
		if (mount.getMountPoint() == "/data") {
			const auto& mntopts = mount.getMountOptions();
			const auto& fm = mntopts.flagmap;
			if (!fm.count("errors"))
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
        //preSpecialize("system_server"); // System server usually doesn't need this level of hiding
		api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api{};
    JNIEnv *env{};
	dev_t dev{};
	ino_t inode{};

    void preSpecialize(const char *process) {
		unsigned int flags = api->getFlags();
		if (flags & zygisk::StateFlag::PROCESS_GRANTED_ROOT) {
			api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
			return;
		}
		if (flags & zygisk::StateFlag::PROCESS_ON_DENYLIST) {
			pid_t pid = getpid();
			int cfd = api->connectCompanion(); // Companion FD
			api->exemptFd(cfd);
			std::tie(dev, inode) = devinoby("libandroid_runtime.so");
			api->pltHookRegister(dev, inode, "unshare", (void*) reshare, (void**) &ar_unshare);
			api->pltHookRegister(dev, inode, "setresuid", (void*) resetresuid, (void**) &ar_setresuid);
			api->pltHookCommit();
			nocb = [pid, cfd, this]() { // Capture this for api access
				nocb = []() {};
                std::vector<std::pair<std::unique_ptr<FileDescriptorInfo>, bool>> fd_sanitize_list; // bool is prefer_detach

                auto fds = GetOpenFds([](const std::string &error){
                    LOGE("[zygisk::PreSpecialize] GetOpenFds: %s", error.c_str());
                });

                if (fds) {
                    for (auto &fd_num : *fds) {
                        if (fd_num == cfd) continue; // Skip companion FD itself

                        auto fdi = FileDescriptorInfo::CreateFromFd(fd_num, [fd_num](const std::string &error){
                            LOGE("[zygisk::PreSpecialize] CreateFromFd(%d): %s", fd_num, error.c_str());
                        });

                        if (fdi) {
                            bool should_sanitize_this_fd = false;
                            bool prefer_detach = false; // True if content/path is sensitive, implies detach

                            if (fdi->is_sock) {
                                std::string socket_name;
                                if (fdi->GetSocketName(&socket_name)) {
                                    if (socket_name.find("magisk") != std::string::npos ||
                                        socket_name.find("kernelsu") != std::string::npos || // For KernelSU daemon, common pattern
                                        socket_name.find("ksud") != std::string::npos || // KernelSU daemon
                                        socket_name.find("apatchd") != std::string::npos || // For APatch daemon, common pattern
                                        socket_name.find("apd") != std::string::npos      // APatch daemon
                                        ) {
                                        LOGD("Marking sensitive socket FD %d (%s) for sanitization.", fd_num, socket_name.c_str());
                                        should_sanitize_this_fd = true;
                                        prefer_detach = true; // Sockets are always detached if sensitive
                                    }
                                }
                            } else { // Not a socket
                                if (!fdi->file_path.starts_with("/memfd:") &&
                                    !fdi->file_path.starts_with("/dev/ashmem") && // Common, usually not root related
                                    !fdi->file_path.starts_with("[anon_inode:") && // e.g., [anon_inode:sync_fence]
                                    !fdi->file_path.empty() // Ensure path is not empty
                                    ) {
                                    
                                    if (fdi->file_path.starts_with(adb_path_prefix) ||
                                        fdi->file_path.find("magisk") != std::string::npos ||
                                        fdi->file_path.find("kernelsu") != std::string::npos ||
                                        fdi->file_path.find("apatch") != std::string::npos) {
                                        LOGD("Marking sensitive file FD %d (%s) for sanitization.", fd_num, fdi->file_path.c_str());
                                        should_sanitize_this_fd = true;
                                        prefer_detach = true; // Sensitive files also detached
                                    }
                                }
                            }

                            if (should_sanitize_this_fd) {
                                fd_sanitize_list.emplace_back(std::move(fdi), prefer_detach);
                            }
                        }
                    }
                }

				int res_unshare = ar_unshare(CLONE_NEWNS);
				if (res_unshare != 0) {
					LOGE("[zygisk::PreSpecialize] ar_unshare: %s", strerror(errno));
                    // Fallback or error handling might be needed if unshare fails critically
				}
				int res_mount_slave = mount("rootfs", "/", nullptr, MS_SLAVE | MS_REC, nullptr);
				if (res_mount_slave != 0) {
					LOGE("[zygisk::PreSpecialize] mount slave: %s", strerror(errno));
                    // Fallback or error handling
				}

				int companion_result = -1;
				if (write(cfd, &pid, sizeof(pid)) != sizeof(pid)) {
					LOGE("[zygisk::PreSpecialize] write to companion: %s", strerror(errno));
				} else {
                    if (read(cfd, &companion_result, sizeof(companion_result)) != sizeof(companion_result)) {
                        LOGE("[zygisk::PreSpecialize] read from companion: %s", strerror(errno));
                        companion_result = -1; // Ensure error state
                    }
                }
				close(cfd);

				if (companion_result == MODULE_CONFLICT) {
					mount(nullptr, "/", nullptr, MS_SHARED | MS_REC, nullptr); // Revert mount changes if conflict
				} else if (companion_result == EXIT_FAILURE) {
					LOGW("[zygisk::PreSpecialize]: Companion failed, fallback to unmount in zygote process");
					unmount(getMountInfo()); // Unmount in current (zygote) namespace as fallback
				}

                // Sanitize FDs after companion communication and potential mount changes
                for (auto &pair_fdi_detach : fd_sanitize_list) {
                    auto& fdi_ptr = pair_fdi_detach.first;
                    bool should_detach = pair_fdi_detach.second;
                    if (fdi_ptr) {
                        LOGD("Sanitizing FD %d (path: %s, socket: %d), detach: %d", 
                                fdi_ptr->fd, fdi_ptr->file_path.c_str(), fdi_ptr->is_sock, should_detach);
                        fdi_ptr->ReopenOrDetach([
                            fd = fdi_ptr->fd, 
                            path = fdi_ptr->file_path // Capture path by value for lambda
                        ](const std::string &error){
                            LOGE("[zygisk::PreSpecialize] Sanitize FD %d (%s): %s", fd, path.c_str(), error.c_str());
                        }, should_detach);
                    }
                }
			};
			return;
		}
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

	void postSpecialize(const char *process) {
        // Unhook PLT hooks
		if (ar_unshare) {
			api->pltHookRegister(dev, inode, "unshare", (void*) ar_unshare, nullptr);
            ar_unshare = nullptr; // Clear pointer
        }
		if (ar_setresuid) {
			api->pltHookRegister(dev, inode, "setresuid", (void*) ar_setresuid, nullptr);
            ar_setresuid = nullptr; // Clear pointer
        }
		api->pltHookCommit();
		api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
	}

};

static void NoRoot(int fd) {
	pid_t pid = -1;
	static unsigned int sucrate = 0;
	static const std::string description = [] {
		std::ifstream f("/data/adb/modules/zygisk_nohello/module.prop");
        std::string desc_content;
        if (f.is_open()) {
            PropertyManager pm_temp("/data/adb/modules/zygisk_nohello/module.prop");
            desc_content = pm_temp.getProp("description", "A Zygisk module to hide root.");
        } else {
            // Fallback if module.prop isn't readable yet, though it should be.
            desc_content = "A Zygisk module to hide root.";
        }
        // Remove any existing status prefix like "[...emoji...] ..." before appending new status
        size_t prefix_end = desc_content.find("] ");
        if (prefix_end != std::string::npos) {
            desc_content = desc_content.substr(prefix_end + 2);
        }
		return desc_content;
	}();

	static const bool compatbility = [] {
		if (fs::exists("/data/adb/modules/zygisk_shamiko") && !fs::exists("/data/adb/modules/zygisk_shamiko/disable"))
			return false;
		if (fs::exists("/data/adb/modules/zygisk-assistant") && !fs::exists("/data/adb/modules/zygisk-assistant/disable"))
			return false;
		return true;
	}();
	int result_status;
	if (read(fd, &pid, sizeof(pid)) != sizeof(pid)) {
        LOGE("[ps::Companion] Failed to read PID: %s", strerror(errno));
		close(fd);
		return;
	}

	PropertyManager pm("/data/adb/modules/zygisk_nohello/module.prop");
	if (!compatbility) {
		result_status = MODULE_CONFLICT;
		pm.setProp("description", "[" + emoji::emojize(":x: ") + "Incompatible environment] " + description);
		goto skip_unmount;
	}

	result_status = forkcall(
		[pid]()
		{
			int res_setns = switchnsto(pid);
			if (!res_setns) { // switchnsto returns true on success (0 from setns)
				LOGE("[ps::Companion] setns failed for PID %d: %s", pid, strerror(errno));
				return EXIT_FAILURE;
			}
			auto mounts = getMountInfo();
			unmount(mounts);
			remount(mounts);
			return EXIT_SUCCESS;
		}
	);

	if (result_status == EXIT_SUCCESS) {
		sucrate++;
		pm.setProp("description", "[" + emoji::emojize(":yum: ") + "Nohello unmounted (" + std::to_string(sucrate) + ") time(s)] " + description);
	} else if (result_status == EXIT_FAILURE) {
        pm.setProp("description", "[" + emoji::emojize(":face_with_thermometer: ") + "Unmount failed in companion] " + description);
    }

skip_unmount:
	if (write(fd, &result_status, sizeof(result_status)) != sizeof(result_status)) {
		LOGE("[ps::Companion] write result to zygote: %s", strerror(errno));
	}
	close(fd);
}

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(NoHello)
REGISTER_ZYGISK_COMPANION(NoRoot)
