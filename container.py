import argparse
import time
from cgroup import *
from unshare import *


def get_json_config(config_file):
    if not os.path.exists(config_file):
        raise Exception('Error: {} not exist, could not get json file'.format(config_file))
    with open(config_file, 'r') as file:
        config = json.load(file)
        return config


def get_value(config, key_list):
    ret = config
    try:
        for key in key_list:
            ret = ret.get(key)
    except KeyError:
        return None
    return ret


def err_exit(msg):
    print(msg)
    sys.exit(1)


def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="container arg")
    parser.add_argument('-config', help='config path')
    args = parser.parse_args()

    # 获取json参数
    config = get_json_config(args.config)

    # 创建 cgroup hierarchy
    cgroup_path = get_value(config, ["linux", "cgroupsPath"])
    if not os.path.exists(cgroup_path):
        os.mkdir(cgroup_path)
    cg = cgroupv1("container_{0}".format(get_value(config,["id"])), get_value(config, ["linux", "resources"]), cgroup_path)

    # 准备root目录
    mount_info = get_value(config, ["root"])
    root = mount_info.get("path")
    image = mount_info.get("bundle")
    if not os.path.exists(root):
        os.mkdir(root)
    if not os.listdir(root):
        subprocess.run(["tar", "-xf", image, "-C", root])

    if not os.path.exists("{0}/put_old".format(root)):
        os.mkdir("{0}/put_old".format(root))

    # 检查是否有root到root的映射
    uid_maps = get_value(config, ["linux", "uidMappings"])
    has_root2root = False
    for uid_map in uid_maps:
        if uid_map.get("containerID") == 0 and uid_map.get("hostID") == 0:
            has_root2root = True
            break
    # 有root用户到root用户的映射，尝试使用所有功能
    if has_root2root:
        print('full function')
        # user namespace
        # if -1 == unshare(CLONE_NEWUSER):
        #     err_exit('unshare user namespace failed')
        # pid namespace
        if -1 == unshare(CLONE_NEWPID):
            err_exit("unshare pid failed")
        child_pid = os.fork()
        if child_pid:
            print("container pid:{0}".format(child_pid))
            print("applying cgroup restrict")
            print("register using:register {0} {1} {2}".format(child_pid, args.config,get_value(config,["id"])))
            cg.apply([child_pid])
            os.waitpid(child_pid, 0)
        else:
            while True:
                time.sleep(1)
                with open("/proc/self/uid_map", "r") as f:
                    if f.read().strip() == '':
                        continue
                with open("/proc/self/gid_map", "r") as f:
                    if f.read().strip() == '':
                        continue
                break
            if -1 == unshare(CLONE_NEWNS):
                err_exit('unshare mount namespace failed')
            subprocess.run(["mount", "--make-rprivate", "/"])
            # 使用pivot_root 改变根目录
            mount_info = get_value(config, ["root"])
            root = mount_info.get("path")
            subprocess.run(["mount", "--bind", root, root])
            os.chdir(root)
            subprocess.run(["pivot_root", '.', "put_old"])
            # uts namespace
            if -1 == unshare(CLONE_NEWUTS):
                err_exit('unshare uts namespace failed')
            hostname = get_value(config, ["hostname"])
            subprocess.run(["hostname", hostname])

            # cgroup namespace
            if -1 == unshare(CLONE_NEWCGROUP):
                err_exit('unshare cgroup namespace failed')
            # ipc namespace
            if -1 == unshare(CLONE_NEWIPC):
                err_exit('unshare ipc namespace failed')
            # net namespace
            if -1 == unshare(CLONE_NEWNET):
                err_exit('unshare net namespace failed')
            subprocess.run(["mount", "-t", "proc", "proc", "/proc"])
            subprocess.run(["mount", "-t", "sysfs", "sysfs", "/sys"])
            # # start container process
            process = get_value(config, ["process"])
            cwd = process.get("cwd")
            env = process.get("env")
            env = {item[0]: item[1] for item in [x.split('=') for x in env]}
            arg = process.get("args")
            os.chdir(cwd)

            os.execve("/bin/sh", arg, env)
    else:
        # 没有root用户到root用户的映射
        # 先使用现有权限把容器创建好，
        print('restricted function')
        # pid namespace
        if -1 == unshare(CLONE_NEWPID):
            err_exit("unshare pid failed")
        child_pid = os.fork()
        if child_pid:
            print("container pid:{0}".format(child_pid))
            print("applying cgroup restrict")
            print("register using:register {0} {1} {2}".format(child_pid, args.config,get_value(config,["id"])))
            # cg.apply([child_pid])
            os.waitpid(child_pid, 0)
        else:
            if -1 == unshare(CLONE_NEWNS):
                err_exit('unshare mount namespace failed')
            subprocess.run(["mount", "--make-rprivate", "/"])
            # 使用pivot_root 改变根目录
            mount_info = get_value(config, ["root"])
            root = mount_info.get("path")
            subprocess.run(["mount", "--bind", root, root])
            os.chdir(root)
            subprocess.run(["pivot_root", '.', "put_old"])
            # uts namespace
            if -1 == unshare(CLONE_NEWUTS):
                err_exit('unshare uts namespace failed')
            hostname = get_value(config, ["hostname"])
            subprocess.run(["hostname", hostname])

            # cgroup namespace
            if -1 == unshare(CLONE_NEWCGROUP):
                err_exit('unshare cgroup namespace failed')
            # ipc namespace
            if -1 == unshare(CLONE_NEWIPC):
                err_exit('unshare ipc namespace failed')
            # net namespace
            if -1 == unshare(CLONE_NEWNET):
                err_exit('unshare net namespace failed')
            subprocess.run(["mount", "-t", "proc", "proc", "/proc"])
            subprocess.run(["mount", "-t", "sysfs", "sysfs", "/sys"])

            # user namespace
            if -1 == unshare(CLONE_NEWUSER):
                err_exit('unshare user namespace failed')
            while True:
                time.sleep(1)
                with open("/proc/self/uid_map", "r") as f:
                    if f.read().strip() == '':
                        continue
                with open("/proc/self/gid_map", "r") as f:
                    if f.read().strip() == '':
                        continue
                break
            # start container process
            process = get_value(config, ["process"])
            cwd = process.get("cwd")
            env = process.get("env")
            env = {item[0]: item[1] for item in [x.split('=') for x in env]}
            arg = process.get("args")
            os.chdir(cwd)

            os.execve("/bin/sh", arg, env)


if __name__ == "__main__":
    sys.exit(main())
