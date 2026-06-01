# 小米充电宝 USB HID 工具

通过 USB HID 协议与小米充电宝通信的工具，支持读取电池信息、Qi2.2 无线充电控制等。

## 安装

### 依赖

- Python 3.8+
- hidapi 系统库

### 系统依赖

**macOS**
```bash
brew install hidapi
```

**Linux**
```bash
sudo apt install libhidapi-hidraw0
# 或
sudo apt install libhidapi-libusb0
```

**Windows**
安装 hidapi 的 Windows 二进制版本，或使用 [Zadig](https://zadig.akeo.ie/) 驱动。

### Python 依赖

```bash
pip install -r requirements.txt
```

## 使用方法

```bash
# 列出已连接的设备
python main.py list

# 显示设备基本信息
python main.py info

# 显示完整信息（包含电池、电芯等）
python main.py info --full

# 获取电池信息
python main.py battery

# 查询 Qi2.2 无线充电状态
python main.py qi2-status

# 开启 Qi2.2
python main.py qi2-enable

# 关闭 Qi2.2
python main.py qi2-disable

# 调试模式（显示 HID 通信日志）
python main.py --debug info --full
```

## 支持的设备

| 型号 ID | 产品名称 | 型号代码 |
|---------|----------|----------|
| 1 | 小米自带线充电宝 10000 67W | PB1067MI |
| 2 | 小米自带线充电宝 10000 口袋版 | P15 |
| 3 | 小米充电宝 自带线 快充版 20000 45W | PB2045MI |
| 4 | 小米自带线充电宝 20000 22.5W | PB2020 |
| 5 | 小米自带线充电宝 20000 67W | PB2067MI |
| 6 | 小米充电宝 Pro 25000 250W | P25 |
| 7 | 小米充电宝 伸缩线 10000 55W | NPB1055R |
| 8 | 小米充电宝 三合一 10000 67W | AC1067 |
| 9 | 小米金沙江充电宝 超薄磁吸 10000 45W | WPB1025S |
| 10 | 小米金沙江充电宝 超薄磁吸 5000 27W | WPB0525S |
| 11 | 小米充电宝 磁吸支架 10000 7.5W 2026版 | WPB1007ZX |
| 12 | 小米充电宝 磁吸自带线 10000 45W | WPB1025 |
| 13 | 小米自带线充电宝 10000 口袋版 2026 | P15 |
| 14 | 小米自带线充电宝 20000 22.5W 2026 | PB2020 |

## Linux 特殊说明

需要添加 udev 规则以便非 root 用户访问 HID 设备：

```bash
# 创建规则文件
sudo tee /etc/udev/rules.d/99-hidapi.rules << 'EOF'
SUBSYSTEM=="usb", ATTR{idVendor}=="2717", MODE="0666"
SUBSYSTEM=="usb", ATTR{idVendor}=="1a86", MODE="0666"
EOF

# 重载规则
sudo udevadm control --reload-rules
sudo udevadm trigger
```

## 通信协议

协议基于 WebHID 逆向分析：
- 帧格式: `HEAD(0xA5) + CMD + LEN + payload + CRC8`
- 帧长度: 32 字节
- CRC-8 多项式: 0x07

## 致谢

协议参考自 [powerbank.mieco.net](https://powerbank.mieco.net/) 网页版的 WebHID 实现。

本项目由 **Opencode + Big Pickle** 驱动。

## 许可证

本项目基于 MIT 许可证开源，详见 [LICENSE](LICENSE)。
