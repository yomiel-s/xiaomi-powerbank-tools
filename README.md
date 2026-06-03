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

设备需要先进入数据传输模式：**连续按 8 次充电宝按钮**（指示灯会进入特定状态），然后通过 USB 线连接电脑。

```bash
# 进入交互模式（保持连接，可持续执行多条命令）
python main.py

# 显示全部信息（电池状态、Qi2.2、电芯温度/电压、电芯编号）
python main.py info

# 开启 Qi2.2 无线充电
python main.py qi2-enable

# 关闭 Qi2.2 无线充电
python main.py qi2-disable

# 发送原始十六进制命令
python main.py raw A5060100C8

# 调试模式（显示 HID 通信日志）
python main.py --debug info
```

### 交互模式

不带参数运行进入交互模式，设备保持连接：

```
xiaomi-pb> info
xiaomi-pb> qi2-enable
xiaomi-pb> qi2-disable
xiaomi-pb> raw A5060100C8
xiaomi-pb> help
xiaomi-pb> exit
```

输出示例：

```
温度点 (1 个):
  #1: 25°C
电芯状态 (2 节):
  #1: 4512mV  0mA
  #2: 4520mV  0mA

电芯编号信息:
  #1: 编码=ATLNWSAR...  生产日期=2026-03-15  厂商代码=ATLN
  #2: 编码=ATLNWSAX...  生产日期=2026-03-15  厂商代码=ATLN
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

### 命令列表

| 发送 CMD | 响应 CMD | 名称 |
|----------|----------|------|
| 0x00 | 0x10 | Hello（握手/心跳） |
| 0x01 | 0x11 | 获取电池信息 |
| 0x02 | 0x12 | 获取电芯状态 |
| 0x03 | 0x13 | 获取历史记录 |
| 0x04 | 0x14 | 获取电芯编号 |
| 0x05 | — | 断开连接 |
| 0x06 | 0x16 | 设置 Qi2.2 |
| 0x07 | 0x17 | 查询 Qi2.2 状态 |
| 0x08 | 0x18 | 电芯温度阈值与型号 |
| 0x0A | — | 心跳（复用 Hello 帧） |

### Hello 帧格式

```
A5 00 0D <4字节时间戳> xiaomi-pb <CRC8>  填充到32字节
```

### 电芯状态帧格式

请求: `A5 02 02 01 <cell_count> <CRC8>`

响应每5字节一组描述一节电芯: `温度(1B,有符号) + 电压(2B, LE) + 电流(2B, LE)`

温度值 `-127` (0x81) 表示无传感器。

### 电芯编号(ID)帧格式

请求: `A5 04 01 <cell_index> <CRC8>`

响应: `状态(1B) + 电芯序号(1B) + ID字符串(ASCII, 最大29B, 空终止)`

ID 字符串格式（9 位固定码）：
- 第 1-4 位: 电芯厂商代码 (ATLN=宁德新能源, EVE1=亿纬锂能, etc.)
- 第 5 位: 产品类型
- 第 6 位: 电池类型
- 第 7 位: 年份编码 (F=2025, G=2026, ...)
- 第 8 位: 月份编码 (1-9, A=10, B=11, C=12)
- 第 9 位: 日编码 (1-9, A=10, ..., 0=31)
- 第 10 位起: 分隔符 + 校验码 + 小米编码 + 可变数据

## 致谢

协议参考自 [powerbank.mieco.net](https://powerbank.mieco.net/) 网页版的 WebHID 实现。

本项目由 **Opencode + Big Pickle** 驱动。

## 许可证

本项目基于 MIT 许可证开源，详见 [LICENSE](LICENSE)。
