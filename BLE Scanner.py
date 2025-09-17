import tkinter as tk
from tkinter import ttk, messagebox
import threading
import platform
import time
import asyncio
import sys

# 尝试导入bleak库
try:
    from bleak import BleakScanner

    BLUETOOTH_AVAILABLE = True
except ImportError:
    BLUETOOTH_AVAILABLE = False
    print("警告: 未安装bleak库。请运行 'pip install bleak' 安装")


class BLEScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("蓝牙扫描工具")
        self.root.geometry("700x550")

        # 蓝牙状态
        self.ble_status = "未知"
        self.scanning = False
        self.scan_task = None
        self.devices_dict = {}  # 用于存储设备信息
        self.auto_scan_active = True  # 控制自动扫描是否激活
        self.current_scan_devices = set()  # 存储当前扫描到的设备地址

        # 排序相关
        self.sort_column = "name"
        self.sort_reverse = False

        # 筛选条件
        self.filter_name = tk.StringVar()
        self.filter_name.trace_add("write", self.on_filter_change)
        self.show_only_named = tk.BooleanVar()
        self.show_only_named.trace_add("write", self.on_filter_change)

        # 创建界面
        self.create_widgets()

        # 开始监测蓝牙状态
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self.monitor_ble_status, daemon=True
        )
        self.monitor_thread.start()

        # 启动自动扫描循环
        self.start_auto_scan()

    def create_widgets(self):
        # 状态显示框架
        status_frame = ttk.LabelFrame(self.root, text="蓝牙状态", padding=(10, 5))
        status_frame.pack(fill=tk.X, padx=10, pady=5)

        self.status_label = ttk.Label(
            status_frame, text="状态: 未知", font=("Arial", 12)
        )
        self.status_label.pack(side=tk.LEFT)

        # 刷新按钮
        self.refresh_button = ttk.Button(
            status_frame, text="刷新设备", command=self.refresh_devices
        )
        self.refresh_button.pack(side=tk.RIGHT)

        # 筛选框架
        filter_frame = ttk.LabelFrame(self.root, text="设备筛选", padding=(10, 5))
        filter_frame.pack(fill=tk.X, padx=10, pady=5)

        # 名称筛选输入框
        ttk.Label(filter_frame, text="名称包含:").pack(side=tk.LEFT)
        self.filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_name)
        self.filter_entry.pack(side=tk.LEFT, padx=(5, 10))

        # 只显示有名称的设备复选框
        self.named_only_check = ttk.Checkbutton(
            filter_frame, text="只显示有名字的设备", variable=self.show_only_named
        )
        self.named_only_check.pack(side=tk.LEFT)

        # 设备列表框架
        devices_frame = ttk.LabelFrame(self.root, text="附近蓝牙设备", padding=(10, 5))
        devices_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 创建表格
        columns = ("name", "address", "rssi")
        self.tree = ttk.Treeview(devices_frame, columns=columns, show="headings")
        self.tree.heading(
            "name", text="名称", command=lambda: self.sort_column_by("name")
        )
        self.tree.heading(
            "address", text="MAC地址", command=lambda: self.sort_column_by("address")
        )
        self.tree.heading(
            "rssi", text="信号强度", command=lambda: self.sort_column_by("rssi")
        )
        self.tree.column("name", width=250)
        self.tree.column("address", width=150)
        self.tree.column("rssi", width=100)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(
            devices_frame, orient=tk.VERTICAL, command=self.tree.yview
        )
        self.tree.configure(yscroll=scrollbar.set)

        # 绑定选中事件
        self.tree.bind("<<TreeviewSelect>>", self.on_device_select)

        # 布局
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 底部信息
        self.info_label = ttk.Label(self.root, text="就绪", foreground="gray")
        self.info_label.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)

    def on_device_select(self, event):
        """设备被选中时的回调函数"""
        self.auto_scan_active = False
        self.info_label.config(text="已选中设备，暂停自动刷新")

    def sort_column_by(self, col):
        """根据指定列排序"""
        # 如果点击的是同一列，则切换排序方向，否则重置为升序
        if self.sort_column == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = col
            self.sort_reverse = False

        # 获取所有项目
        items = [
            (self.tree.set(item, col), item) for item in self.tree.get_children("")
        ]

        # 根据列的类型进行排序
        if col == "rssi":
            # 信号强度按数值排序
            items.sort(
                key=lambda x: int(x[0]) if x[0].lstrip("-").isdigit() else -1000,
                reverse=self.sort_reverse,
            )
        else:
            # 其他列按字符串排序
            items.sort(reverse=self.sort_reverse)

        # 重新排列项目
        for index, (val, item) in enumerate(items):
            self.tree.move(item, "", index)

    def on_filter_change(self, *args):
        """筛选条件改变时的回调函数"""
        # 在新线程中应用筛选条件
        filter_thread = threading.Thread(target=self.apply_filters, daemon=True)
        filter_thread.start()

    def apply_filters(self):
        """应用筛选条件"""
        # 获取筛选条件
        filter_text = self.filter_name.get().strip().lower()
        show_only_named = self.show_only_named.get()

        # 重新检查所有已存在的设备是否符合筛选条件
        devices_to_remove = []
        for address, (name, rssi) in self.devices_dict.items():
            # 检查名称筛选
            name_match = not filter_text or filter_text in name.lower()

            # 检查是否只显示有名字的设备
            named_device = not show_only_named or (name and name != "未知设备")

            # 如果不符合筛选条件，标记为移除
            if not (name_match and named_device):
                devices_to_remove.append(address)

        # 在主线程中更新界面
        self.root.after(
            0, self.update_tree_view, filter_text, show_only_named, devices_to_remove
        )

    def update_tree_view(self, filter_text, show_only_named, devices_to_remove):
        """更新树形视图"""
        # 移除不符合筛选条件的设备
        for address in devices_to_remove:
            # 在树形视图中查找并删除设备
            children = self.tree.get_children()
            for child in children:
                item = self.tree.item(child)
                if item["values"][1] == address:
                    self.tree.delete(child)
                    break
            # 从字典中移除设备
            if address in self.devices_dict:
                del self.devices_dict[address]

        # 更新状态信息，显示当前列表中的设备总数
        total_devices = len(self.tree.get_children())
        self.info_label.config(text=f"设备列表中共有 {total_devices} 个设备")

    def get_ble_status(self):
        """
        获取蓝牙状态
        """
        if not BLUETOOTH_AVAILABLE:
            return "不支持蓝牙"

        try:
            # 在Windows上检查蓝牙支持
            system = platform.system()
            if system == "Windows":
                try:
                    import wmi

                    c = wmi.WMI()
                    # 检查蓝牙无线电
                    radios = c.Win32_PnPEntity(Name="*Bluetooth*")
                    if radios:
                        return "蓝牙已启用"

                    # 检查蓝牙服务
                    services = c.Win32_Service(Name="bthserv")
                    if services and services[0].State == "Running":
                        return "蓝牙已启用"
                except ImportError:
                    # 如果没有wmi，则假设蓝牙可用
                    return "蓝牙已启用"

            # 在其他平台上假设蓝牙可用
            return "蓝牙已启用"

        except Exception as e:
            print(f"检查蓝牙状态时出错: {e}")
            return "蓝牙已禁用"

    def monitor_ble_status(self):
        """
        监测蓝牙状态
        """
        while self.monitoring:
            status = self.get_ble_status()
            if status != self.ble_status:
                self.ble_status = status
                # 在主线程中更新界面
                self.root.after(0, self.update_status_display)

            # 每5秒检查一次状态
            time.sleep(5)

    def update_status_display(self):
        """
        更新状态显示
        """
        self.status_label.config(text=f"状态: {self.ble_status}")

        # 根据状态改变颜色
        if self.ble_status == "不支持蓝牙":
            self.status_label.config(foreground="red")
        elif self.ble_status == "蓝牙已禁用":
            self.status_label.config(foreground="orange")
        elif self.ble_status == "蓝牙已启用":
            self.status_label.config(foreground="green")
        elif self.ble_status == "蓝牙已连接":
            self.status_label.config(foreground="blue")

    def start_auto_scan(self):
        """
        启动自动扫描循环
        """
        if self.auto_scan_active:
            self.refresh_devices()
            # 10秒后再次扫描
            self.root.after(10000, self.start_auto_scan)
        else:
            # 1秒后检查是否应该恢复扫描
            self.root.after(1000, self.start_auto_scan)

    def refresh_devices(self):
        """
        刷新设备列表
        """
        # 清空当前扫描设备集合
        self.current_scan_devices.clear()

        self.info_label.config(text="正在扫描设备...")

        # 在新线程中执行扫描
        scan_thread = threading.Thread(target=self.scan_devices, daemon=True)
        scan_thread.start()

    def scan_devices(self):
        """
        扫描附近的蓝牙设备
        """
        try:
            if not BLUETOOTH_AVAILABLE or self.ble_status in [
                "不支持蓝牙",
                "蓝牙已禁用",
            ]:
                self.root.after(0, lambda: self.info_label.config(text="蓝牙不可用"))
                return

            # 初始化计数器
            self.device_count = 0

            # 使用asyncio运行异步扫描
            asyncio.run(self.async_scan())

            # 扫描完成后，移除当前扫描中未发现的设备
            self.root.after(0, self.cleanup_missing_devices)

        except Exception as e:
            error_msg = f"扫描设备时出错: {str(e)}"
            print(error_msg)
            self.root.after(0, lambda: self.info_label.config(text="扫描失败"))
            messagebox.showerror("错误", error_msg)

    def cleanup_missing_devices(self):
        """清理当前扫描中未发现的设备"""
        # 获取当前列表中的所有设备地址
        existing_items = {}
        for child in self.tree.get_children():
            item = self.tree.item(child)
            address = item["values"][1]
            existing_items[address] = child

        # 移除在当前扫描中未发现的设备
        for address, child in existing_items.items():
            if address not in self.current_scan_devices:
                self.tree.delete(child)
                if address in self.devices_dict:
                    del self.devices_dict[address]

        # 更新状态信息，显示当前列表中的设备总数
        total_devices = len(self.tree.get_children())
        self.info_label.config(text=f"设备列表中共有 {total_devices} 个设备")

    def detection_callback(self, device, advertisement_data):
        """
        设备发现回调函数
        """
        name = device.name or "未知设备"
        address = device.address
        # 从设备对象获取RSSI值，如果没有则从advertisement_data获取
        rssi = getattr(device, "rssi", None)
        if rssi is None and advertisement_data:
            rssi = (
                advertisement_data.rssi
                if hasattr(advertisement_data, "rssi")
                else "N/A"
            )
        if rssi is None:
            rssi = "N/A"

        # 添加到当前扫描设备集合
        self.current_scan_devices.add(address)

        # 应用筛选条件
        # 检查名称筛选
        filter_text = self.filter_name.get().strip().lower()
        if filter_text and filter_text not in name.lower():
            return  # 不匹配筛选条件，跳过该设备

        # 检查是否只显示有名字的设备
        if self.show_only_named.get() and (not device.name or name == "未知设备"):
            return  # 设置了只显示有名字的设备，但当前设备没有名字，跳过

        # 检查设备是否已存在于字典中
        if address in self.devices_dict:
            # 如果设备已存在且名称或信号强度有变化，则更新
            if self.devices_dict[address] != (name, rssi) and (
                name != "未知设备" or self.devices_dict[address][0] == "未知设备"
            ):
                self.devices_dict[address] = (name, rssi)
                # 更新界面显示
                children = self.tree.get_children()
                for child in children:
                    item = self.tree.item(child)
                    if item["values"][1] == address:
                        self.root.after(
                            0,
                            lambda cid=child, n=name, addr=address, r=rssi: self.tree.item(
                                cid, values=(n, addr, r)
                            ),
                        )
                        break
        else:
            # 新设备
            self.devices_dict[address] = (name, rssi)
            self.device_count += 1

            # 在主线程中更新界面
            self.root.after(
                0,
                lambda n=name, a=address, r=rssi: self.tree.insert(
                    "", "end", values=(n, a, r)
                ),
            )

            # 更新状态信息
            total_devices = len(self.tree.get_children())
            self.root.after(
                0,
                lambda t=total_devices: self.info_label.config(
                    text=f"设备列表中共有 {t} 个设备"
                ),
            )

    async def async_scan(self):
        """
        异步扫描蓝牙设备（实时更新模式）
        """
        try:
            # 创建带有回调函数的扫描器实例
            scanner = BleakScanner(detection_callback=self.detection_callback)

            # 开始扫描
            await scanner.start()
            # 扫描5秒
            await asyncio.sleep(5.0)
            # 停止扫描
            await scanner.stop()

            # 更新最终状态
            total_devices = len(self.tree.get_children())
            self.root.after(
                0,
                lambda t=total_devices: self.info_label.config(
                    text=f"设备列表中共有 {t} 个设备"
                ),
            )

        except Exception as e:
            raise e


def main():
    root = tk.Tk()
    app = BLEScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
