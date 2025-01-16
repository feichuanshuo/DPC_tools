from configuration import adb_path

# 检查设备是否已经root
root_cmd = [adb_path, "shell", "su -c 'exit'"]

# 获取连接的Android设备的CPU架构
detecting_phone_architecture_cmd = [adb_path, "shell", "su -c 'getprop ro.product.cpu.abi'"]

# 启动adb服务器
start_adb_cmd = [adb_path, "start-server"]

# 停止adb服务器
stop_adb_cmd = [adb_path, "kill-server"]

# 在设备上禁用SELinux，这通常是进行调试和其他高级操作所必需的。
colse_SELinux_cmd = [adb_path, "shell", "su -c 'setenforce 0'"]

# https://github.com/frida/frida/issues/1788
# 禁用USAP池
close_usap_cmd = [
    adb_path,
    "shell",
    "su -c 'setprop persist.device_config.runtime_native.usap_pool_enabled false'",
]

# 在设备上杀死任何正在运行的Frida服务器实例
kill_cmd = [adb_path, "shell", "su -c 'pkill -9 -f hluda'"]

# 删除设备上/data/local/tmp目录中的所有文件。
clean_cmd = [adb_path, "shell", "su -c 'rm -rf /data/local/tmp/*'"]