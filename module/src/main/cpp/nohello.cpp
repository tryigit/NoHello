#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>
#include <filesystem>
#include <ranges>
#include <vector>
#include <utility>
#include <sys/mount.h>
#include <endian.h>
#include <thread>
#include <fstream>
#include <sstream>
#include <sys/wait.h>
#include <optional>
#include <functional>
#include <stdexcept>
#include <cstring>
#include <link.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>


#include "zygisk.hpp"
#include "external/android_filesystem_config.h"
#include "mountsinfo.cpp"
#include "external/fdutils/fd_utils.cpp"
#include "log.h"
#include "PropertyManager.cpp"
#include "external/emoji.h"

namespace fs = std::filesystem;

static constexpr off_t EXT_SUPERBLOCK_OFFSET = 0x400;
static constexpr off_t EXT_MAGIC_OFFSET = 0x38;
static constexpr off_t EXT_ERRORS_OFFSET = 0x3C;
static constexpr uint16_t EXT_MAGIC = 0xEF53;

#define MODULE_CONFLICT  2

static const std::set<std::string> toumount_sources = {"KSU", "APatch", "magisk", "worker"};
static const std::string adbPathPrefix = "/data/adb";

std::pair<dev_t, ino_t> devinobymap(const std::string& lib, bool useFind = false, unsigned int *ln = nullptr) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    unsigned int index = 0;
    std::string needle = "/" + lib;
    if (!maps.is_open()) {
        if (ln) *ln = static_cast<unsigned int>(-1);
        return {dev_t(0), ino_t(0)};
    }
    while (std::getline(maps, line)) {
        if (line.size() >= needle.size() && ((useFind && line.find(needle) != std::string::npos) ||
            line.compare(line.size() - needle.size(), needle.size(), needle) == 0)) {
            std::istringstream iss(line);
            std::string addr, perms, offset, dev_str, inode_str;
            iss >> addr >> perms >> offset >> dev_str >> inode_str;
            std::istringstream devsplit(dev_str);
            std::string major_hex, minor_hex;
            if (std::getline(devsplit, major_hex, ':') &&
                std::getline(devsplit, minor_hex)) {
                try {
                    int major = std::stoi(major_hex, nullptr, 16);
                    int minor = std::stoi(minor_hex, nullptr, 16);
                    dev_t devnum = makedev(major, minor);
                    ino_t inode = std::stoul(inode_str);
                    if (ln)
                        *ln = index;
                    maps.close();
                    return {devnum, inode};
                } catch (const std::invalid_argument& ia) {
                } catch (const std::out_of_range& oor) {
                }
            }
        }
        index++;
    }
    maps.close();
    if (ln)
        *ln = static_cast<unsigned int>(-1);
    return {dev_t(0), ino_t(0)};
}

std::optional<std::pair<dev_t, ino_t>> devinoby(const char* lib_name_needle) {
    struct State {
        const char* needle;
        std::optional<std::pair<dev_t, ino_t>> result;
    } state = { lib_name_needle, std::nullopt };

    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        auto* s = static_cast<State*>(data);
        if (info->dlpi_name && info->dlpi_name[0]) {
            const char* basename = strrchr(info->dlpi_name, '/');
            if (basename) {
                basename++;
            } else {
                basename = info->dlpi_name;
            }
            if (strcmp(basename, s->needle) == 0) {
                struct stat st{};
                if (stat(info->dlpi_name, &st) == 0) {
                    s->result = std::make_pair(st.st_dev, st.st_ino);
                    return 1;
                }
            }
        }
        return 0;
    }, &state);
    return state.result;
}

int forkcall(const std::function<int()>& lambda) {
    pid_t pid = fork();
    if (pid == -1)
        return -1;
    if (pid == 0) {
        exit(lambda());
    } else {
        int status = -1;
        if (waitpid(pid, &status, 0) == pid) {
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            }
        }
    }
    return -1;
}

bool switchnsto(pid_t pid) {
    if (pid <= 0) return false;
    std::string path = "/proc/" + std::to_string(pid) + "/ns/mnt";
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd != -1) {
        int res = setns(fd, 0);
        close(fd);
        return res == 0;
    } else {
        LOGE("open(\"%s\"): %s", path.c_str(), strerror(errno));
    }
    return false;
}


static bool anomaly(MountRootResolver mrs, const MountInfo &mount) {
	const std::string resolved_root = mrs.resolveRoot(mount);
	if (resolved_root.starts_with(adbPathPrefix) || mount.getMountPoint().starts_with(adbPathPrefix)) {
		return true;
	}
	const auto& fs_type = mount.getFsType();
	const auto& mnt_src = mount.getMountSource();
	if (toumount_sources.count(mnt_src)) {
		return true;
	}
	if (fs_type == "overlay") {
		if (toumount_sources.count(mnt_src)) {
			return true;
		}
		const auto& fm = mount.getMountOptions().flagmap;
		if (fm.count("lowerdir") && fm.at("lowerdir").starts_with(adbPathPrefix)) {
			return true;
		}
		if (fm.count("upperdir") && fm.at("upperdir").starts_with(adbPathPrefix)) {
			return true;
		}
		if (fm.count("workdir") && fm.at("workdir").starts_with(adbPathPrefix)) {
			return true;
		}
	} else if (fs_type == "tmpfs") {
		if (toumount_sources.count(mnt_src)) {
			return true;
		}
	}
	return false;
}

static std::pair<bool, bool> anomaly(const std::unique_ptr<FileDescriptorInfo> fdi) {
	if (fdi->is_sock) {
		std::string socket_name;
		if (fdi->GetSocketName(&socket_name)) {
			if (socket_name.find("magisk") != std::string::npos ||
				socket_name.find("kernelsu") != std::string::npos ||
				socket_name.find("ksud") != std::string::npos ||
				socket_name.find("apatchd") != std::string::npos ||
				socket_name.find("apd") != std::string::npos
					) {
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
			if (fdi->file_path.starts_with(adbPathPrefix) ||
				fdi->file_path.find("magisk") != std::string::npos ||
				fdi->file_path.find("kernelsu") != std::string::npos ||
				fdi->file_path.find("apatch") != std::string::npos) {
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
	if (!mntsrc || mntsrc.gcount() != sizeof(magic)) {
        mntsrc.close();
		return nullptr;
    }
	magic = le16toh(magic);
	if (magic != EXT_MAGIC) {
        mntsrc.close();
		return nullptr;
    }
	uint16_t errors;
	mntsrc.seekg(EXT_SUPERBLOCK_OFFSET + EXT_ERRORS_OFFSET, std::ios::beg);
	mntsrc.read(reinterpret_cast<char *>(&errors), sizeof(errors));
    mntsrc.close();
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
				LOGD("mount(nullptr, \"/data\", nullptr, 0x%x, \"errors=%s\"): returned 0: 0 (Success)", flags, errors->c_str());
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

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

class NoHello : public zygisk::ModuleBase {
public:
    void onLoad(Api *_api, JNIEnv *_env) override {
        this->api = _api;
        this->env = _env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
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
		api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api{};
    JNIEnv *env{};
	int cfd{};
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
			cfd = api->connectCompanion();
			api->exemptFd(cfd);

			auto di_optional = devinoby("libandroid_runtime.so");

			if (di_optional) {
				LOGI("$[zygisk::PreSpecialize] Using dl_iterate_phdr (via devinoby) to find libandroid_runtime.so for PLT hooking.");
				std::tie(dev, inode) = *di_optional;
			} else {
				LOGW("$[zygisk::PreSpecialize] devinoby (dl_iterate_phdr) failed. Falling back to devinobymap (/proc/self/maps).");
				std::tie(dev, inode) = devinobymap("libandroid_runtime.so");
				if (!dev && !inode) {
					LOGE("$[zygisk::PreSpecialize] devinobymap: Failed to get device & inode for libandroid_runtime.so from /proc/self/maps.");
					close(cfd);
					api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
					return;
				}
			}

			if (!dev && !inode) {
				LOGE("$[zygisk::PreSpecialize] Critical error: Could not obtain dev and inode for libandroid_runtime.so.");
				close(cfd);
				api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
				return;
			}

			api->pltHookRegister(dev, inode, "unshare", (void*) reshare, (void**) &ar_unshare);
			api->pltHookRegister(dev, inode, "setresuid", (void*) resetresuid, (void**) &ar_setresuid);
			api->pltHookCommit();
			nocb = [pid, this]() {
				nocb = []() {};
                std::vector<std::pair<std::unique_ptr<FileDescriptorInfo>, bool>> fdSanitizeList;
                auto fds = GetOpenFds([](const std::string &error){
                    LOGE("#[zygisk::PreSpecialize] GetOpenFds: %s", error.c_str());
                });
                if (fds) {
                    for (auto &fd_val : *fds) {
                        if (fd_val == cfd) continue;
                        auto fdi = FileDescriptorInfo::CreateFromFd(fd_val, [fd_val](const std::string &error){
                            LOGE("#[zygisk::PreSpecialize] CreateFromFd(%d): %s", fd_val, error.c_str());
                        });
						if (!fdi)
							continue;
                        
                        std::unique_ptr<FileDescriptorInfo> fdi_moved = std::move(fdi);
                        auto [canSanitize, shouldDetach] = anomaly(std::const_pointer_cast<FileDescriptorInfo>(fdi_moved));

                        if (canSanitize) {
							fdSanitizeList.emplace_back(std::move(fdi_moved), shouldDetach);
						}
                    }
                }

				int res = ar_unshare(CLONE_NEWNS);
				if (res != 0) {
					LOGE("#[zygisk::PreSpecialize] ar_unshare: %s", strerror(errno));
					close(cfd);
					return;
				}
				res = mount("rootfs", "/", nullptr, MS_SLAVE | MS_REC, nullptr);
				if (res != 0) {
					LOGE("#[zygisk::PreSpecialize] mount(rootfs, \"/\", nullptr, MS_SLAVE | MS_REC, nullptr): returned %d: %d (%s)", res, errno, strerror(errno));
					close(cfd);
					return;
				}

				if (write(cfd, &pid, sizeof(pid)) != sizeof(pid)) {
					LOGE("#[zygisk::PreSpecialize] write: [-> pid]: %s", strerror(errno));
					res = EXIT_FAILURE;
                } else if (read(cfd, &res, sizeof(res)) != sizeof(res)) {
					LOGE("#[zygisk::PreSpecialize] read: [<- status]: %s", strerror(errno));
					res = EXIT_FAILURE;
				}

				close(cfd);

				if (res == MODULE_CONFLICT) {
					mount(nullptr, "/", nullptr, MS_SHARED | MS_REC, nullptr);
					return;
				} else if (res == EXIT_FAILURE) {
					LOGW("#[zygisk::PreSpecialize]: Companion failed, fallback to unmount in zygote process");
					unmount(getMountInfo());
				}

                for (auto &[fdi_entry, shouldDetach] : fdSanitizeList) {
                    if (fdi_entry) {
                        LOGD("#[zygisk::PreSpecialize]: Sanitizing FD %d (path: %s, socket: %d), detach: %d",
                                fdi_entry->fd, fdi_entry->file_path.c_str(), fdi_entry->is_sock, shouldDetach);
                        fdi_entry->ReopenOrDetach([
                            fd_capture = fdi_entry->fd,
                            path_capture = fdi_entry->file_path
                        ](const std::string &error){
                            LOGE("#[zygisk::PreSpecialize] Sanitize FD %d (%s): %s", fd_capture, path_capture.c_str(), error.c_str());
                        }, shouldDetach);
                    }
                }
			};
			return;
		}
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

	void postSpecialize(const char *process) {
		if (ar_unshare) {
			api->pltHookRegister(dev, inode, "unshare", (void*) ar_unshare, nullptr);
            ar_unshare = nullptr;
        }
		if (ar_setresuid) {
			api->pltHookRegister(dev, inode, "setresuid", (void*) ar_setresuid, nullptr);
            ar_setresuid = nullptr;
        }
		api->pltHookCommit();
		api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
	}

};

static void NoRoot(int fd) {
	pid_t pid = -1;
	static unsigned int successRate = 0;
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
        LOGE("#[ps::Companion] Failed to read PID: %s", strerror(errno));
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
				LOGE("#[ps::Companion] setns failed for PID %d: %s", pid, strerror(errno));
				return EXIT_FAILURE;
			}
			auto mounts = getMountInfo();
			unmount(mounts);
			remount(mounts);
			return EXIT_SUCCESS;
		}
	);
	if (result == EXIT_SUCCESS) {
		successRate++;
		pm.setProp("description", "[" + emoji::emojize(":yum: ") + "Nohello unmounted " +
								  std::to_string(successRate) + " time(s)] " + description);
	}
	skip:
	if (write(fd, &result, sizeof(result)) != sizeof(result)) {
		LOGE("#[ps::Companion] Failed to write result: %s", strerror(errno));
	}
	close(fd);
}

REGISTER_ZYGISK_MODULE(NoHello)
REGISTER_ZYGISK_COMPANION(NoRoot)
