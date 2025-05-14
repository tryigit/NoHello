#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>
#include <filesystem>
#include <ranges>
#include <vector>
#include <utility>
#include <set>
#include <string_view>
#include <sys/mount.h>
#include <endian.h>
#include <thread>
#include <link.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <cstdio> // For FILE*

#include "zygisk.hpp"
#include "external/android_filesystem_config.h"
#include "mountsinfo.cpp"
#include "utils.cpp"
#include "external/fdutils/fd_utils.cpp"
#include "log.h"
#include "PropertyManager.cpp"
#include "external/emoji.h"


static FILE *(*original_fopen)(const char *filename, const char *mode) = nullptr;
static FILE *(*original_fopen64)(const char *filename, const char *mode) = nullptr;
static int (*original_unshare)(int flags) = nullptr;
static int (*original_setresuid)(uid_t ruid, uid_t euid, uid_t suid) = nullptr;
static int (*original_setresgid)(gid_t rgid, gid_t egid, gid_t sgid) = nullptr;


static const std::set<std::string_view> sensitive_proc_files = {
    "/proc/mounts",
    "/proc/self/mounts",
    "/proc/self/mountinfo",
    "/proc/modules",
    "/proc/vmallocinfo",
    "/proc/kallsyms",
    "/proc/cpuinfo",
    "/proc/stat",
    "/proc/vmstat",
    "/proc/version",
    "/proc/cmdline",
    "/proc/self/cmdline",
    "/proc/self/status",
    "/proc/self/maps",
    "/proc/self/smaps",
    "/proc/1/maps",
    "/proc/1/smaps",
    "/proc/1/cmdline",
    "/proc/1/status",
    "/system/build.prop",
    "/vendor/build.prop",
    "/default.prop"
};

static const std::vector<std::string_view> sensitive_path_keywords = {
    "magisk",
    "kernelsu",
    "apatch",
    "/data/adb",
    "riru",
    "zygisk",
    "lsposed",
    "edxposed",
    "xposed",
    "shamiko",
    "supersu",
    "kingroot",
    "substrate"
};

static bool is_path_sensitive(std::string_view path) {
    if (path.empty()) return false;

    for (const auto& keyword : sensitive_path_keywords) {
        if (path.find(keyword) != std::string_view::npos) {
            return true;
        }
    }
    if (path.starts_with("/proc/")) {
        if (sensitive_proc_files.count(path)) {
            return true;
        }
        // Check for /proc/[pid]/maps or similar for sensitive PIDs if needed
        // e.g. if path starts with /proc/1/ (init process)
    }
    return false;
}

static FILE *hooked_fopen(const char *filename, const char *mode) {
    if (filename && is_path_sensitive(filename)) {
        LOGW("#[NoHello::hooked_fopen] Blocked: Access to '%s' denied.", filename);
        errno = EACCES;
        return nullptr;
    }
    return original_fopen(filename, mode);
}

static FILE *hooked_fopen64(const char *filename, const char *mode) {
    if (filename && is_path_sensitive(filename)) {
        LOGW("#[NoHello::hooked_fopen64] Blocked: Access to '%s' denied.", filename);
        errno = EACCES;
        return nullptr;
    }
    return original_fopen64(filename, mode);
}

static int hooked_unshare(int flags) {
    NoHello::nocb_instance();
    errno = 0;
    return flags == CLONE_NEWNS ? 0 : original_unshare(flags & ~CLONE_NEWNS);
}

static int hooked_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
    NoHello::nocb_instance();
    return original_setresuid(ruid, euid, suid);
}

static int hooked_setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
    NoHello::nocb_instance();
    return original_setresgid(rgid, egid, sgid);
}


using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

namespace fs = std::filesystem;

static constexpr off_t EXT_SUPERBLOCK_OFFSET = 0x400;
static constexpr off_t EXT_MAGIC_OFFSET = 0x38;
static constexpr off_t EXT_ERRORS_OFFSET = 0x3C;
static constexpr uint16_t EXT_MAGIC = 0xEF53;

#define MODULE_CONFLICT  2

static const std::set<std::string> toumount_sources = {"KSU", "APatch", "magisk", "worker", "mirror", "overlay"};
static const std::string adbPathPrefix = "/data/adb";
static const std::string magiskLoopPrefix = "/dev/block/loop";


static bool anomaly(MountRootResolver mrs, const MountInfo &mount) {
	const std::string resolved_root = mrs.resolveRoot(mount);
    std::string mount_point_str = mount.getMountPoint();
    std::string mount_source_str = mount.getMountSource();

	if (is_path_sensitive(resolved_root) || is_path_sensitive(mount_point_str)) {
		return true;
	}

	const auto& fs_type = mount.getFsType();

	if (toumount_sources.count(mount_source_str) || toumount_sources.count(fs_type)) {
		return true;
	}

	if (fs_type == "overlay") {
		const auto& fm = mount.getMountOptions().flagmap;
		if (fm.count("lowerdir") && is_path_sensitive(fm.at("lowerdir"))) return true;
		if (fm.count("upperdir") && is_path_sensitive(fm.at("upperdir"))) return true;
		if (fm.count("workdir") && is_path_sensitive(fm.at("workdir"))) return true;
	} else if (fs_type == "tmpfs") {
        if (is_path_sensitive(mount_source_str)) return true;
	}
	return false;
}

static std::pair<bool, bool> anomaly(const std::unique_ptr<FileDescriptorInfo>& fdi) {
    if (!fdi) return {false, false};

	if (fdi->is_sock) {
		std::string socket_name;
		if (fdi->GetSocketName(&socket_name)) {
			if (is_path_sensitive(socket_name)) {
				LOGD("Marking sensitive socket FD %d (%s) for sanitization.", fdi->fd, socket_name.c_str());
				return {true, true};
			}
		}
	} else {
		if (!fdi->file_path.starts_with("/memfd:") &&
			!fdi->file_path.starts_with("/dev/ashmem") &&
			!fdi->file_path.starts_with("[anon_inode:") &&
			!fdi->file_path.empty()
				) {
			if (is_path_sensitive(fdi->file_path)) {
				LOGD("Marking sensitive file FD %d (%s) for sanitization.", fdi->fd, fdi->file_path.c_str());
				return {true, true};
			}
		}
	}
	return {false, false};
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

static void unmount_sensitive(const std::vector<MountInfo>& mounts) {
	MountRootResolver mrs(mounts);
	for (const auto& mount : std::ranges::reverse_view(mounts)) {
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

static void remount_data(const std::vector<MountInfo>& mounts) {
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
			if (mntflags & MountFlags::NOSUID) flags |= MS_NOSUID;
			if (mntflags & MountFlags::NODEV) flags |= MS_NODEV;
			if (mntflags & MountFlags::NOEXEC) flags |= MS_NOEXEC;
			if (mntflags & MountFlags::NOATIME) flags |= MS_NOATIME;
			if (mntflags & MountFlags::NODIRATIME) flags |= MS_NODIRATIME;
			if (mntflags & MountFlags::RELATIME) flags |= MS_RELATIME;
			if (mntflags & MountFlags::NOSYMFOLLOW) flags |= MS_NOSYMFOLLOW;

			int res;
			std::string errors_opt = "errors=" + *errors;
			if ((res = ::mount(nullptr, "/data", nullptr, flags, errors_opt.c_str())) == 0)
				LOGD("mount(nullptr, \"/data\", nullptr, 0x%x, \"%s\"): returned 0: 0 (Success)", flags, errors_opt.c_str());
			else
				LOGW("mount(NULL, \"/data\", NULL, 0x%x, \"%s\"): returned %d: %d (%s)", flags, errors_opt.c_str(), res, errno, strerror(errno));
			break;
		}
	}
}


class NoHello : public zygisk::ModuleBase {
public:
    static std::function<void()> nocb_instance;

    void onLoad(Api *_api, JNIEnv *_env) override {
        this->api = _api;
        this->env = _env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *process_name_chars = env->GetStringUTFChars(args->nice_name, nullptr);
        std::string process_name = process_name_chars ? process_name_chars : "";
        env->ReleaseStringUTFChars(args->nice_name, process_name_chars);

        unsigned int flags = api->getFlags();

		if (flags & zygisk::StateFlag::PROCESS_GRANTED_ROOT) {
			api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
			return;
		}

        bool is_sensitive_process = false;
        // Add your logic here to determine if 'process_name' is sensitive
        // For example, check against a list of banking apps, etc.
        // if (process_name == "com.example.bankapp") is_sensitive_process = true;

		if ((flags & zygisk::StateFlag::PROCESS_ON_DENYLIST) || is_sensitive_process) {
			pid_t pid = getpid();
			cfd = api->connectCompanion();
			if (cfd != -1) {
                api->exemptFd(cfd);
            } else {
                LOGE("#[zygisk::PreSpecialize] Failed to connect to companion for %s", process_name.c_str());
            }

            auto di_libc = devinoby("libc.so");
            if (di_libc) {
                std::tie(libc_dev, libc_inode) = *di_libc;
                api->pltHookRegister(libc_dev, libc_inode, "fopen", (void*) hooked_fopen, (void**) &original_fopen);
                api->pltHookRegister(libc_dev, libc_inode, "fopen64", (void*) hooked_fopen64, (void**) &original_fopen64);
                LOGD("Registered fopen hooks from libc.so for %s", process_name.c_str());
            } else {
                LOGW("#[zygisk::PreSpecialize] devino[dl_iterate_phdr]: Failed for libc.so in %s", process_name.c_str());
            }

			auto di_runtime = devinoby("libandroid_runtime.so");
			if (di_runtime) {
				std::tie(runtime_dev, runtime_inode) = *di_runtime;
                api->pltHookRegister(runtime_dev, runtime_inode, "unshare", (void*) hooked_unshare, (void**) &original_unshare);
                api->pltHookRegister(runtime_dev, runtime_inode, "setresuid", (void*) hooked_setresuid, (void**) &original_setresuid);
                api->pltHookRegister(runtime_dev, runtime_inode, "setresgid", (void*) hooked_setresgid, (void**) &original_setresgid);
                LOGD("Registered unshare/setresuid/setresgid hooks from libandroid_runtime.so for %s", process_name.c_str());
			} else {
				LOGW("#[zygisk::PreSpecialize] devino[dl_iterate_phdr]: Failed for libandroid_runtime.so in %s", process_name.c_str());
			}

			if (!api->pltHookCommit()) {
                LOGE("#[zygisk::PreSpecialize] pltHookCommit failed for %s", process_name.c_str());
            } else {
                 LOGD("pltHookCommit successful for %s", process_name.c_str());
            }

			NoHello::nocb_instance = [pid, this, process_name]() {
				NoHello::nocb_instance = []() {};
                std::vector<std::pair<std::unique_ptr<FileDescriptorInfo>, bool>> fdSanitizeList;
                auto fds = GetOpenFds([](const std::string &error){
                    LOGE("#[zygisk::PreSpecialize::nocb] GetOpenFds: %s", error.c_str());
                });

                if (fds) {
                    for (auto &fd_val : *fds) {
                        if (cfd != -1 && fd_val == cfd) continue;
                        auto fdi = FileDescriptorInfo::CreateFromFd(fd_val, [fd_val](const std::string &error){
                            LOGE("#[zygisk::PreSpecialize::nocb] CreateFromFd(%d): %s", fd_val, error.c_str());
                        });
						if (!fdi) continue;
						auto [canSanitize, shouldDetach] = anomaly(fdi);
                        if (canSanitize) {
							fdSanitizeList.emplace_back(std::move(fdi), shouldDetach);
						}
                    }
                }

				int unshare_res = original_unshare ? original_unshare(CLONE_NEWNS) : syscall(SYS_unshare, CLONE_NEWNS);
				if (unshare_res != 0) {
					LOGE("#[zygisk::PreSpecialize::nocb] unshare(CLONE_NEWNS) failed for %s: %s", process_name.c_str(), strerror(errno));
                    if (cfd != -1) close(cfd);
					return;
				}
				int mount_slave_res = mount("rootfs", "/", nullptr, MS_SLAVE | MS_REC, nullptr);
				if (mount_slave_res != 0) {
					LOGE("#[zygisk::PreSpecialize::nocb] mount(rootfs, \"/\", nullptr, MS_SLAVE | MS_REC, nullptr) failed for %s: %d (%s)", process_name.c_str(), errno, strerror(errno));
                    if (cfd != -1) close(cfd);
					return;
				}

                int companion_res = EXIT_FAILURE;
                if (cfd != -1) {
                    if (write(cfd, &pid, sizeof(pid)) != sizeof(pid)) {
                        LOGE("#[zygisk::PreSpecialize::nocb] write [-> pid] to companion failed for %s: %s", process_name.c_str(), strerror(errno));
                    } else if (read(cfd, &companion_res, sizeof(companion_res)) != sizeof(companion_res)) {
                        LOGE("#[zygisk::PreSpecialize::nocb] read [<- status] from companion failed for %s: %s", process_name.c_str(), strerror(errno));
                    }
                    close(cfd);
                    cfd = -1;
                }


				if (companion_res == MODULE_CONFLICT) {
					mount(nullptr, "/", nullptr, MS_SHARED | MS_REC, nullptr);
                    LOGW("#[zygisk::PreSpecialize::nocb] Module conflict reported by companion for %s. Reverted mount changes.", process_name.c_str());
					return;
				} else if (companion_res == EXIT_FAILURE) {
					LOGW("#[zygisk::PreSpecialize::nocb]: Companion failed or unavailable for %s, fallback to unmount in zygote process", process_name.c_str());
					unmount_sensitive(getMountInfo());
				}


                for (auto &[fdi_ptr, shouldDetach] : fdSanitizeList) {
                    if (fdi_ptr) {
                        LOGD("#[zygisk::PreSpecialize::nocb]: Sanitizing FD %d (path: %s, socket: %d), detach: %d for %s",
                                fdi_ptr->fd, fdi_ptr->file_path.c_str(), fdi_ptr->is_sock, shouldDetach, process_name.c_str());
                        fdi_ptr->ReopenOrDetach([&](const std::string &error){
                            LOGE("#[zygisk::PreSpecialize::nocb] Sanitize FD %d (%s): %s for %s", fdi_ptr->fd, fdi_ptr->file_path.c_str(), error.c_str(), process_name.c_str());
                        }, shouldDetach);
                    }
                }
			};
			if (original_unshare == nullptr || original_setresuid == nullptr || original_setresgid == nullptr) {
                 LOGW("#[zygisk::PreSpecialize] One or more libandroid_runtime hooks (unshare/setresuid/setresgid) are not set up for %s, nocb might not trigger as expected.", process_name.c_str());
            }
            if (original_fopen == nullptr || original_fopen64 == nullptr) {
                LOGW("#[zygisk::PreSpecialize] One or more libc hooks (fopen/fopen64) are not set up for %s.", process_name.c_str());
            }
			return;
		}
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

	void postAppSpecialize(const AppSpecializeArgs *args) override {
        const char *process_name_chars = env->GetStringUTFChars(args->nice_name, nullptr);
        std::string process_name = process_name_chars ? process_name_chars : "";
        env->ReleaseStringUTFChars(args->nice_name, process_name_chars);

        bool unhooked = false;
		if (original_fopen) {
			api->pltHookRegister(libc_dev, libc_inode, "fopen", (void*) original_fopen, nullptr);
            original_fopen = nullptr;
            unhooked = true;
        }
		if (original_fopen64) {
			api->pltHookRegister(libc_dev, libc_inode, "fopen64", (void*) original_fopen64, nullptr);
            original_fopen64 = nullptr;
            unhooked = true;
        }
		if (original_unshare) {
			api->pltHookRegister(runtime_dev, runtime_inode, "unshare", (void*) original_unshare, nullptr);
            original_unshare = nullptr;
            unhooked = true;
        }
		if (original_setresuid) {
			api->pltHookRegister(runtime_dev, runtime_inode, "setresuid", (void*) original_setresuid, nullptr);
            original_setresuid = nullptr;
            unhooked = true;
        }
        if (original_setresgid) {
			api->pltHookRegister(runtime_dev, runtime_inode, "setresgid", (void*) original_setresgid, nullptr);
            original_setresgid = nullptr;
            unhooked = true;
        }

		if (unhooked) {
            if(!api->pltHookCommit()){
                 LOGE("#[zygisk::PostSpecialize] pltHookCommit failed during unhook for %s", process_name.c_str());
            } else {
                 LOGD("#[zygisk::PostSpecialize] pltHookCommit successful during unhook for %s", process_name.c_str());
            }
        }

        if (cfd != -1) {
            close(cfd);
            cfd = -1;
        }
		api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
	}

    void preServerSpecialize(ServerSpecializeArgs *args) override {
		api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api{};
    JNIEnv *env{};
	int cfd = -1;
	dev_t libc_dev{};
	ino_t libc_inode{};
    dev_t runtime_dev{};
	ino_t runtime_inode{};
};

std::function<void()> NoHello::nocb_instance = []() {};


static void NoRootCompanion(int client_fd) {
	pid_t target_pid = -1;
	static unsigned int successRate = 0;
	static const std::string description = [] {
		std::ifstream f("/data/adb/modules/zygisk_nohello/description");
		return f ? std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>()) : "A Zygisk module to hide root.";
	}();

	static const bool compatibility = [] {
		if (fs::exists("/data/adb/modules/zygisk_shamiko") && !fs::exists("/data/adb/modules/zygisk_shamiko/disable"))
			return false;
		if (fs::exists("/data/adb/modules/zygisk-assistant") && !fs::exists("/data/adb/modules/zygisk-assistant/disable"))
			return false;
		return true;
	}();

	int result_status;
	if (read(client_fd, &target_pid, sizeof(target_pid)) != sizeof(target_pid)) {
        LOGE("#[ps::Companion] Failed to read PID: %s", strerror(errno));
		close(client_fd);
		return;
	}

	PropertyManager pm("/data/adb/modules/zygisk_nohello/module.prop");
	if (!compatibility) {
		result_status = MODULE_CONFLICT;
		pm.setProp("description", "[" + emoji::emojize(":x: ") + "Incompatible environment] " + description);
		goto send_result;
	}

	result_status = forkcall(
		[target_pid]()
		{
			if (!switchnsto(target_pid)) {
				LOGE("#[ps::Companion::fork] setns failed for PID %d: %s", target_pid, strerror(errno));
				return EXIT_FAILURE;
			}
			auto mounts = getMountInfo();
			unmount_sensitive(mounts);
			remount_data(mounts);
			return EXIT_SUCCESS;
		}
	);

	if (result_status == EXIT_SUCCESS) {
		successRate++;
		pm.setProp("description", "[" + emoji::emojize(":yum: ") + "NoHello unmounted " +
								  std::to_string(successRate) + " time(s)] " + description);
	} else {
        LOGE("#[ps::Companion] Forked process for PID %d failed with status %d", target_pid, result_status);
    }

	send_result:
	if (write(client_fd, &result_status, sizeof(result_status)) != sizeof(result_status)) {
		LOGE("#[ps::Companion] Failed to write result_status: %s", strerror(errno));
	}
	close(client_fd);
}

REGISTER_ZYGISK_MODULE(NoHello)
REGISTER_ZYGISK_COMPANION(NoRootCompanion)
