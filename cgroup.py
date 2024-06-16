import json
import os
import subprocess
import sys
import traceback


def find_subsystem_dir(subsystem):
    # find in cgroup v1
    out_string = subprocess.check_output(['mount', '--type', 'cgroup']).decode().rstrip()
    if out_string:
        for line in out_string.split('\n'):
            attr = line.split(' ')[-1].strip('(').strip(')').split(',')
            if subsystem in attr:
                index = attr.index(subsystem) - len(attr)
                directory = line.split(' ')[2]
                return line.split(' ')[2], 1
    # find in cgroup v2
    out_string = subprocess.check_output(['mount', '--type', 'cgroup2']).decode().rstrip()
    for line in out_string.split('\n'):
        cg_dir = line.split(' ')[2]
        with open(os.path.join(cg_dir, "cgroup.subtree_control"), "r") as f:
            subsystems = f.readline()
        if subsystem in subsystems:
            return cg_dir, 2
    return None, None


def mount_subsystem_v1(subsystem, directory, name=""):
    if find_subsystem_dir(subsystem) != (None, None):
        raise CgroupError("subsystem {0} already mount".format(subsystem))
    subprocess.run(["mount", "-t", "cgroup", "-o", subsystem, name, directory])


def write_value(directory, filename, content):
    if os.path.exists(os.path.join(directory, filename)):
        with open(os.path.join(directory, filename), "w") as f:
            print("writing {0} {1}".format(filename, str(content)))
            f.write(str(content))
    else:
        print("file {0} not exist".format(os.path.join(directory, filename)))


def cfg_cpu(directory, config):
    write_value(directory, "cpu.cfs_quota_us", config.get("quota"))
    write_value(directory, "cpu.cfs_period_us", config.get("period"))
    write_value(directory, "cpu.shares", config.get("shares"))
    # write_value(directory, "cpu.rt_runtime_us", config.get("realtimeRuntime"))
    # write_value(directory, "cpu.rt_period_us", config.get("realtimePeriod"))


def cfg_cpuset(directory, config):
    write_value(directory, "cpuset.cpus", config.get("cpus"))
    write_value(directory, "cpuset.mems", config.get("mems"))


def cfg_memory(directory, config):
    write_value(directory, "memory.limit_in_bytes", config.get("limit"))
    write_value(directory, "memory.soft_limit_in_bytes", config.get("reservation"))
    write_value(directory, "memory.memsw.limit_in_bytes", int(config.get("limit")) + int(config.get("swap")))
    write_value(directory, "memory.kmem.limit_in_bytes", config.get("kernel"))
    write_value(directory, "memory.kmem.tcp.limit_in_bytes", config.get("kernelTCP"))
    write_value(directory, "memory.swappiness", config.get("swappiness"))

    write_value(directory, "memory.swappiness", config.get("swappiness"))

    if config.get("disableOOMKiller"):
        write_value(directory, "memory.oom_control", '1')
    else:
        write_value(directory, "memory.oom_control", '0')


def cfg_network(directory, config):
    write_value(directory, "net_cls.classid", config.get("classID"))
    value = ""
    for kv in config.get("priorities"):
        value += "{0} {1}\n".format(kv.get("name"), kv.get("priority"))
    write_value(directory, "net_prio.ifpriomap", value)


def cfg_blkio(directory, config):
    # write_value(directory,"blkio.weight",config.get("weight"))
    # write_value(directory, "blkio.weight_device", config.get("weightDevice"))
    # leafWeight
    data = ""
    for each in config.get("throttleReadBpsDevice"):
        data += "{0}:{1} {2}\n".format(each.get("major"), each.get("minor"), each.get("rate"))
    write_value(directory, "blkio.throttle.read_bps_device", data)
    data = ""
    for each in config.get("throttleWriteIOPSDevice"):
        data += "{0}:{1} {2}\n".format(each.get("major"), each.get("minor"), each.get("rate"))
    write_value(directory, "blkio.throttle.write_iops_device", data)


def cfg_devices(directory, config):
    # 先执行所有deny
    for device in config:
        dev_type = device.get("type") if device.get("type") else "a"
        dev_major = device.get("major") if device.get("major") else "*"
        dev_minor = device.get("minor") if device.get("minor") else "*"
        dev_access = device.get("access") if device.get("access") else "rwm"
        if device.get("deny"):
            write_value(directory, "devices.deny",
                        "{0} {1}:{2} {3}".format(dev_type, dev_major, dev_minor, dev_access))
    # 再执行所有allow
    for device in config:
        dev_type = device.get("type") if device.get("type") else "a"
        dev_major = device.get("major") if device.get("major") else "*"
        dev_minor = device.get("minor") if device.get("minor") else "*"
        dev_access = device.get("access") if device.get("access") else "rwm"
        if device.get("allow"):
            write_value(directory, "devices.allow",
                        "{0} {1}:{2} {3}".format(dev_type, dev_major, dev_minor, dev_access))


def cfg_hugetlb(directory, config):
    for limit in config:
        name = limit.get("pageSize")
        limitation = limit.get("limit")
        if os.path.exists("hugetlb.{0}.limit_in_bytes".format(name)):
            write_value(directory, "hugetlb.{0}.limit_in_bytes", limitation)
        else:
            print("pageSize {0} not recognized/supported".format(name))


def cfg_pids(directory, config):
    pid_max = config.get("limit")
    write_value(directory, "pids.max", pid_max)


class CgroupError(Exception):
    def __init__(self, message, status=-1):
        super().__init__(message, status)
        self.message = message
        self.status = status


def keys2subsystems(keys):
    result = []
    for key in keys:
        if key == "cpu":
            result += ["cpu", "cpuset"]
        elif key == "memory":
            result += ["memory"]
        elif key == "network":
            result += ["net_cls", "net_prio"]
        elif key == "pids":
            result += ["pids"]
        elif key == "hugepageLimits":
            result += ["hugetlb"]
        elif key == "devices":
            result += ["devices"]
        elif key == "blockIO":
            result += ["blkio"]
        else:
            raise CgroupError("subsystem config name {0} not recognised".format(key))
    return result


def subsystem2key(subsystem):
    if subsystem in ["cpu", "cpuset"]:
        result = "cpu"
    elif subsystem == "memory":
        result = "memory"
    elif subsystem in ["net_cls", "net_prio"]:
        result = "network"
    elif subsystem == "pids":
        result = "pids"
    elif subsystem == "hugetlb":
        result = "hugepageLimits"
    elif subsystem == "devices":
        result = "devices"
    elif subsystem == "blkio":
        result = "blockIO"
    else:
        raise CgroupError("subsystem name {0} not recognised".format(subsystem))
    return result


class cgroupv1:
    def __init__(self, name, config, cgroup_base_dir):
        self.config = config
        self.subsystem_info = {}
        self.name = name
        self.cgroup_base_dir = cgroup_base_dir
        try:
            # print(key2subsystem(config.keys()))
            for subsystem in keys2subsystems(config.keys()):
                # 创建subsystem信息记录项
                self.subsystem_info.update({subsystem: {}})
                subsystem_dir, version = find_subsystem_dir(subsystem)
                if not subsystem_dir:
                    subsystem_dir = os.path.join(self.cgroup_base_dir, subsystem)
                    os.mkdir(subsystem_dir)
                    mount_subsystem_v1(subsystem, subsystem_dir, subsystem)
                    self.subsystem_info.get(subsystem).update({"mount_by_hand": True})
                elif version == 2:
                    raise CgroupError("cpu subsystem in cgroup2")
                self.subsystem_info.get(subsystem).update({"mount_point": subsystem_dir})

                # 创建cgroup目录
                if not os.path.exists("{0}/{1}".format(subsystem_dir, self.name)):
                    print("mkdir {0}/{1}".format(subsystem_dir, self.name))
                    os.mkdir("{0}/{1}".format(subsystem_dir, self.name))

                # 写入配置信息
                key = subsystem2key(subsystem)
                subsystem_config = config.get(key)
                if globals().get("cfg_{0}".format(subsystem)):
                    print("calling cfg_{0}".format(subsystem))
                    globals().get("cfg_{0}".format(subsystem))("{0}/{1}".format(subsystem_dir, self.name), subsystem_config)

        except BaseException as e:
            print(traceback.format_exc())
            self.clean()
            sys.exit(-1)

    # 根据subsystem_info中记录的信息，清理创建的目录和挂载点
    def clean(self):
        print("start cleaning")
        for key in self.subsystem_info:
            subsystem = self.subsystem_info.get(key)
            subsystem_dir = subsystem.get("mount_point")
            if not subsystem_dir:
                continue
            # 删除创建的cgroup目录
            if os.path.exists("{0}/{1}".format(subsystem_dir, self.name)):
                try:
                    with open("{0}/{1}/cgroup.procs".format(subsystem_dir, self.name), "r") as f:
                        process_list = [x.strip() for x in f.read().strip().split('\n')]
                    for process in process_list:
                        with open("{0}/cgroup.procs".format(subsystem_dir), "w") as f:
                            f.write(process)
                except OSError as e:
                    print("rmdir {0}/{1} failed".format(subsystem_dir, self.name))
                    print(traceback.format_exc())
                    continue
                print("doing rmdir {0}/{1}".format(subsystem_dir, self.name))
                try:
                    os.rmdir("{0}/{1}".format(subsystem_dir, self.name))
                except OSError as e:
                    print("rmdir {0}/{1} failed".format(subsystem_dir, self.name))
                    print(traceback.format_exc())

            # 如果subsystem是手动挂载的，那么移除
            if subsystem.get("mount_by_hand"):
                if os.path.exists(subsystem_dir):
                    print("doing umount {0}".format(subsystem_dir))
                    try:
                        subprocess.run(["umount", subsystem_dir])
                    except BaseException as e:
                        print("doing umount {0} failed".format(subsystem_dir))
                        print(traceback.format_exc())
                    print("doing rmdir {0}".format(subsystem_dir))
                    try:
                        os.rmdir(subsystem_dir)
                    except OSError as e:
                        print("rmdir {0} failed".format(subsystem_dir))
                        print(traceback.format_exc())

        print("cleaning finished")

    # 将一组进程放到所有subsystem的控制下
    def apply(self, process_list):
        for key in self.subsystem_info:
            subsystem = self.subsystem_info.get(key)
            subsystem_dir = subsystem.get("mount_point")
            for process in process_list:
                with open("{0}/{1}/{2}".format(subsystem_dir, self.name, "cgroup.procs"), "w") as f:
                    f.write(str(process))


def test():
    def get_json_config(config_file):
        if not os.path.exists(config_file):
            raise FileNotFoundError('Error: {} not exist, could not get json file'.format(config_file))
        with open(config_file, 'r') as file:
            config = json.load(file)
            return config

    config = get_json_config("./test/config.json")
    tmp = cgroupv1("container_test", config.get("resources"), "/tmp/cgroup")
    while True:
        cmd = input("cmd:")
        cmd = cmd.split(',')
        if cmd[0]=='a':
            tmp.apply([cmd[1]])
        elif cmd[0] =='q':
            tmp.clean()
            break
        else:
            continue


if __name__ == "__main__":
    test()
