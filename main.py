#!/usr/bin/env python3
"""
小米充电宝 USB HID 通信工具

从网页版 (https://powerbank.mieco.net/) 逆向提取的通信协议，
通过 WebHID → Python hidapi 移植。

依赖: pip install hidapi

用法:
  # 列出设备
  python xiaomi_pb.py list

  # 连接并显示完整信息
  python xiaomi_pb.py info

  # 查询 Qi2.2 状态
  python xiaomi_pb.py qi2-status

  # 开启 Qi2.2
  python xiaomi_pb.py qi2-enable

  # 关闭 Qi2.2
  python xiaomi_pb.py qi2-disable

  # 获取电池信息
  python xiaomi_pb.py battery
"""

import argparse
import struct
import sys
import time
from datetime import datetime, timezone, timedelta

try:
    import hid
except ImportError:
    print("需要安装 hidapi: pip install hidapi", file=sys.stderr)
    sys.exit(1)


# --- 常量 ---
VIDS = [0x2717, 0x1A86]  # 10007, 6790
FRAME_SIZE = 32
HEAD = 0xA5

# 命令码 (发送)
CMD_HELLO = 0x00
CMD_GET_BATTERY_INFO = 0x01
CMD_GET_CELL_STATUS = 0x02
CMD_GET_HISTORY = 0x03
CMD_GET_BATTERY_ID = 0x04
CMD_DISCONNECT = 0x05
CMD_ENABLE_QI2 = 0x06
CMD_GET_QI2_STATUS = 0x07
CMD_GET_CELL_TEMP_MODEL = 0x08
CMD_HEARTBEAT = 0x0A

# 命令码 (响应)
RSP_HELLO = 0x10
RSP_BATTERY_INFO = 0x11
RSP_CELL_STATUS = 0x12
RSP_HISTORY = 0x13
RSP_BATTERY_ID = 0x14
RSP_ENABLE_QI2 = 0x16
RSP_QI2_STATUS = 0x17
RSP_CELL_TEMP_MODEL = 0x18

MODEL_DB = [
    (1, "小米自带线充电宝 10000 67W", "PB1067MI"),
    (2, "小米自带线充电宝 10000 口袋版", "P15"),
    (3, "小米充电宝 自带线 快充版 20000 45W", "PB2045MI"),
    (4, "小米自带线充电宝 20000 22.5W", "PB2020"),
    (5, "小米自带线充电宝 20000 67W", "PB2067MI"),
    (6, "小米充电宝 Pro 25000 250W", "P25"),
    (7, "小米充电宝 伸缩线 10000 55W", "NPB1055R"),
    (8, "小米充电宝 三合一 10000 67W", "AC1067"),
    (9, "小米金沙江充电宝 超薄磁吸 10000 45W", "WPB1025S"),
    (10, "小米金沙江充电宝 超薄磁吸 5000 27W", "WPB0525S"),
    (11, "小米充电宝 磁吸支架 10000 7.5W 2026版", "WPB1007ZX"),
    (12, "小米充电宝 磁吸自带线 10000 45W", "WPB1025"),
    (13, "小米自带线充电宝 10000 口袋版 2026", "P15"),
    (14, "小米自带线充电宝 20000 22.5W 2026", "PB2020"),
]


def crc8(data: bytes) -> int:
    """CRC-8 校验 (多项式 0x07, 与网页端一致)"""
    t = 0
    for byte in data:
        t ^= byte
        for _ in range(8):
            if t & 0x80:
                t = (t << 1) ^ 0x07
            else:
                t <<= 1
            t &= 0xFF
    return t


def build_command_frame(cmd: int, payload: bytes = b"") -> bytes:
    """构建命令帧: HEAD + CMD + LEN + payload + CRC8，填充到 32 字节"""
    data_len = len(payload)
    header = bytes([HEAD, cmd, data_len])
    frame = header + payload
    ck = crc8(frame)
    full = frame + bytes([ck])
    # 填充到 FRAME_SIZE 字节
    return full.ljust(FRAME_SIZE, b'\x00')


def build_hello_frame() -> bytes:
    """构建 Hello 握手帧 (特殊格式)"""
    frame = bytearray(FRAME_SIZE)
    frame[0] = HEAD
    frame[1] = CMD_HELLO
    frame[2] = 13  # data length
    ts = int(time.time()) + 28800  # UTC+8 时间戳
    struct.pack_into('<I', frame, 3, ts)
    magic = b"xiaomi-pb"
    frame[7:7 + len(magic)] = magic
    # CRC over bytes 0..15
    ck = crc8(bytes(frame[:16]))
    frame[16] = ck
    return bytes(frame)


def parse_response(data: bytes) -> dict:
    """解析响应帧，返回 {cmd, payload, crc_ok, error}"""
    if len(data) < 4:
        return {"error": "数据长度不足"}
    if data[0] != HEAD:
        return {"error": f"帧头错误: 期望 0xA5, 实际 0x{data[0]:02X}"}
    cmd = data[1]
    payload_len = data[2]
    # payload 从第 3 字节开始，长度由 data[2] 决定
    actual_payload_len = min(payload_len, len(data) - 4)
    payload = data[3:3 + actual_payload_len]
    received_crc = data[3 + actual_payload_len]
    # CRC 检查：对 HEAD + CMD + LEN + payload 做校验
    crc_data = bytes([HEAD, cmd, payload_len]) + payload
    expected_crc = crc8(crc_data)
    return {
        "cmd": cmd,
        "payload": payload,
        "payload_len": payload_len,
        "crc_ok": received_crc == expected_crc,
        "crc_received": received_crc,
        "crc_expected": expected_crc,
        "error": None,
    }


# --- 响应解码器 ---

def decode_hello_response(payload: bytes) -> dict:
    """Hello 响应 (CMD 0x10)，包含设备型号"""
    if len(payload) < 23:
        return {"error": "Hello 响应数据不足"}
    model_id = struct.unpack_from('<H', payload, 0)[0]
    sn_bytes = payload[2:22]
    sn = sn_bytes.split(b'\x00')[0].decode('ascii', errors='replace')
    status_code = payload[22] if len(payload) > 22 else 0
    status_map = {0: "空闲", 1: "充电中", 2: "放电中"}
    status = status_map.get(status_code, f"未知({status_code})")
    model_name = "--"
    model_model = "--"
    for mid, name, model in MODEL_DB:
        if mid == model_id:
            model_name = name
            model_model = model
            break
    return {
        "device_name": model_name,
        "device_model": model_model,
        "model_id": model_id,
        "serial_number": sn,
        "charging_status": status,
    }


def decode_battery_payload(payload: bytes) -> dict:
    """电池信息响应 (CMD 0x11)"""
    if len(payload) < 18:
        return {"error": f"电池数据不足 {len(payload)}/18"}
    status = payload[0]
    activate = payload[1]
    cycle_count = struct.unpack_from('<H', payload, 2)[0]
    battery_health = struct.unpack_from('<H', payload, 4)[0]
    charge_err = payload[6]
    chg_state = (charge_err >> 6) & 3
    fault_type = charge_err & 0x3F
    chg_map = {0: "放电", 1: "充电", 2: "空闲"}
    error_value = struct.unpack_from('<H', payload, 7)[0]
    history_errors = struct.unpack_from('<H', payload, 9)[0]
    cell_config = payload[11]
    level = payload[12]
    temp_raw = payload[13]
    temp = temp_raw if temp_raw < 128 else temp_raw - 256
    voltage = struct.unpack_from('<H', payload, 14)[0]
    current = struct.unpack_from('<H', payload, 16)[0]
    # 处理符号电流
    if current > 32767:
        current -= 65536
    return {
        "status": "成功" if status == 0 else f"失败({status})",
        "activate": "已激活" if activate == 1 else "未激活" if activate == 0 else f"保留({activate})",
        "cycle_count": cycle_count,
        "health": battery_health,
        "charge_state": chg_map.get(chg_state, f"未知({chg_state})"),
        "fault_type": fault_type,
        "level_pct": level,
        "temperature_c": temp,
        "voltage_mv": voltage,
        "current_ma": current,
    }


def decode_qi2_status(payload: bytes) -> dict:
    """Qi2.2 状态响应 (CMD 0x17)"""
    if len(payload) < 2:
        return {"error": "QI2 状态数据不足"}
    status = payload[0]
    enabled = payload[1] == 1
    return {
        "success": status == 0,
        "enabled": enabled,
        "status_text": "已开启" if enabled else "未开启",
    }


def decode_qi2_enable_response(payload: bytes) -> dict:
    """Qi2.2 使能响应 (CMD 0x16)"""
    if len(payload) < 1:
        return {"error": "QI2 使能响应数据不足"}
    status = payload[0]
    return {
        "success": status == 0,
        "description": "设置成功" if status == 0 else "设置失败",
    }


def decode_cell_status(payload: bytes) -> dict:
    """电芯状态响应 (CMD 0x12)"""
    if len(payload) < 1:
        return {"error": "电芯数据不足"}
    status = payload[0]
    if status != 0:
        return {"status": f"失败({status})", "cells": []}
    cells = []
    cell_size = 5
    num_cells = (len(payload) - 1) // cell_size
    for i in range(num_cells):
        offset = 1 + i * cell_size
        if offset + cell_size > len(payload):
            break
        t_raw = payload[offset]
        t = t_raw if t_raw < 128 else t_raw - 256
        v = struct.unpack_from('<H', payload, offset + 1)[0]
        c = struct.unpack_from('<H', payload, offset + 3)[0]
        if c > 32767:
            c -= 65536
        cells.append({
            "index": i + 1,
            "temp_c": t,
            "voltage_mv": v,
            "current_ma": c,
        })
    return {"status": "成功", "cells": cells}


def decode_cell_temp_model(payload: bytes) -> dict:
    """电芯温度阈值与型号响应 (CMD 0x18)"""
    if len(payload) < 5:
        return {"error": "温度阈值数据不足"}
    status = payload[0]
    raw_high = struct.unpack_from('<h', payload, 1)[0]
    raw_low = struct.unpack_from('<h', payload, 3)[0]
    model_bytes = payload[5:].split(b'\x00')[0]
    model_str = model_bytes.decode('ascii', errors='replace')
    return {
        "success": status == 0,
        "high_temp": raw_high,
        "low_temp": raw_low,
        "battery_model": model_str,
    }


# --- HID 设备操作 ---

def find_device():
    """查找第一个匹配的小米充电宝 HID 设备"""
    for vid in VIDS:
        devices = hid.enumerate(vid, 0)
        if devices:
            return devices[0]
    return None


def list_devices():
    """列出所有匹配设备"""
    all_devices = []
    for vid in VIDS:
        all_devices.extend(hid.enumerate(vid, 0))
    return all_devices


class XiaomiPowerBank:
    """小米充电宝 HID 通信封装"""

    def __init__(self, debug=False):
        self.device = None
        self.debug = debug

    def log(self, msg):
        if self.debug:
            print(f"[HID] {msg}", file=sys.stderr)

    def connect(self, dev_info=None):
        if dev_info is None:
            dev_info = find_device()
        if dev_info is None:
            print("未找到小米充电宝设备，请检查 USB 连接", file=sys.stderr)
            return False
        path = dev_info["path"]
        self.log(f"打开设备: {dev_info.get('product_string', '?')} "
                 f"VID=0x{dev_info['vendor_id']:04X} PID=0x{dev_info['product_id']:04X}")
        self.device = hid.device()
        try:
            self.device.open_path(path)
        except OSError as e:
            print(f"无法打开设备: {e}", file=sys.stderr)
            print("提示: 在 Linux 上可能需要 udev 规则; macOS 上需允许输入监控", file=sys.stderr)
            return False
        return True

    def disconnect(self):
        if self.device:
            try:
                frame = build_command_frame(CMD_DISCONNECT)
                self._write(frame)
            except Exception:
                pass
            try:
                self.device.close()
            except Exception:
                pass
            self.device = None

    def _write(self, data: bytes):
        """发送 HID 报告 (report ID = 0)"""
        # hidapi write: 首字节为 report ID
        report = b'\x00' + data
        self.log(f"发送 {len(data)} 字节: {data.hex()}")
        self.device.write(report)

    def _read(self, timeout_ms=3000) -> bytes:
        """读取 HID 输入报告"""
        data = self.device.read(64, timeout_ms=timeout_ms)
        if data:
            self.log(f"收到 {len(data)} 字节: {bytes(data).hex()}")
            return bytes(data)
        return b''

    def send_and_wait(self, frame: bytes, expected_cmd: int = None, timeout=3000) -> dict:
        """发送帧并等待响应"""
        self._write(frame)
        deadline = time.time() + timeout / 1000
        while time.time() < deadline:
            remaining = int((deadline - time.time()) * 1000)
            if remaining <= 0:
                break
            raw = self._read(timeout_ms=min(remaining, 3000))
            if not raw:
                continue
            result = parse_response(raw)
            if result["error"]:
                self.log(f"解析错误: {result['error']}")
                continue
            if expected_cmd is not None and result["cmd"] != expected_cmd:
                self.log(f"忽略非预期命令: 0x{result['cmd']:02X}, 期望 0x{expected_cmd:02X}")
                continue
            return result
        return {"error": "响应超时"}

    def handshake(self) -> dict:
        """Hello 握手，获取设备信息"""
        frame = build_hello_frame()
        result = self.send_and_wait(frame, expected_cmd=RSP_HELLO, timeout=3000)
        if result["error"]:
            return result
        info = decode_hello_response(result["payload"])
        info["_raw"] = result
        return info

    def get_battery_info(self) -> dict:
        """获取电池组信息"""
        frame = build_command_frame(CMD_GET_BATTERY_INFO)
        result = self.send_and_wait(frame, expected_cmd=RSP_BATTERY_INFO, timeout=3000)
        if result["error"]:
            return result
        info = decode_battery_payload(result["payload"])
        info["_raw"] = result
        return info

    def get_qi2_status(self) -> dict:
        """查询 Qi2.2 状态"""
        frame = build_command_frame(CMD_GET_QI2_STATUS)
        result = self.send_and_wait(frame, expected_cmd=RSP_QI2_STATUS, timeout=3000)
        if result["error"]:
            return result
        info = decode_qi2_status(result["payload"])
        info["_raw"] = result
        return info

    def set_qi2(self, enable: bool) -> dict:
        """开启或关闭 Qi2.2"""
        payload = bytes([1 if enable else 0])
        frame = build_command_frame(CMD_ENABLE_QI2, payload)
        result = self.send_and_wait(frame, expected_cmd=RSP_ENABLE_QI2, timeout=5000)
        if result["error"]:
            return result
        info = decode_qi2_enable_response(result["payload"])
        info["_raw"] = result
        return info

    def get_cell_status(self) -> dict:
        """获取电芯状态"""
        frame = build_command_frame(CMD_GET_CELL_STATUS)
        result = self.send_and_wait(frame, expected_cmd=RSP_CELL_STATUS, timeout=3000)
        if result["error"]:
            return result
        info = decode_cell_status(result["payload"])
        info["_raw"] = result
        return info

    def get_cell_temp_model(self) -> dict:
        """获取电芯温度阈值与型号"""
        frame = build_command_frame(CMD_GET_CELL_TEMP_MODEL)
        result = self.send_and_wait(frame, expected_cmd=RSP_CELL_TEMP_MODEL, timeout=3000)
        if result["error"]:
            return result
        info = decode_cell_temp_model(result["payload"])
        info["_raw"] = result
        return info

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.disconnect()


# --- CLI ---

def cmd_list(args):
    devices = list_devices()
    if not devices:
        print("未找到小米充电宝设备")
        return
    for d in devices:
        print(f"  VID=0x{d['vendor_id']:04X}  PID=0x{d['product_id']:04X}")
        print(f"  产品: {d.get('product_string', '?')}")
        print(f"  序列号: {d.get('serial_number', '?')}")
        print(f"  路径: {d['path']}")
        print()


def cmd_info(args):
    with XiaomiPowerBank(debug=args.debug) as pb:
        if not pb.connect():
            return
        info = pb.handshake()
        if info.get("error"):
            print(f"握手失败: {info['error']}")
            return
        print(f"设备: {info['device_name']} ({info['device_model']})")
        print(f"型号ID: {info['model_id']}")
        print(f"序列号: {info['serial_number']}")
        print(f"充电状态: {info['charging_status']}")
        print()
        if args.full:
            batt = pb.get_battery_info()
            if "error" not in batt:
                print(f"电池:")
                print(f"  状态: {batt['status']}")
                print(f"  激活: {batt['activate']}")
                print(f"  电量: {batt['level_pct']}%")
                print(f"  循环: {batt['cycle_count']} 次")
                print(f"  健康度: {batt['health']}")
                print(f"  温度: {batt['temperature_c']}°C")
                print(f"  电压: {batt['voltage_mv']}mV")
                print(f"  电流: {batt['current_ma']}mA")
                print(f"  充放电: {batt['charge_state']}")
                print()
            qi2 = pb.get_qi2_status()
            if "error" not in qi2:
                print(f"Qi2.2: {qi2['status_text']}")
                print()
            cells = pb.get_cell_status()
            if "error" not in cells and cells.get("cells"):
                print(f"电芯 ({len(cells['cells'])} 节):")
                for c in cells["cells"]:
                    print(f"  #{c['index']}: {c['temp_c']}°C  {c['voltage_mv']}mV  {c['current_ma']}mA")
                print()
            temp = pb.get_cell_temp_model()
            if "error" not in temp:
                print(f"电芯型号: {temp.get('battery_model', '?')}")
                print(f"温度阈值: {temp['low_temp']}°C ~ {temp['high_temp']}°C")


def cmd_battery(args):
    with XiaomiPowerBank(debug=args.debug) as pb:
        if not pb.connect():
            return
        pb.handshake()
        batt = pb.get_battery_info()
        if batt.get("error"):
            print(f"获取电池信息失败: {batt['error']}")
            return
        print(f"电量: {batt['level_pct']}%")
        print(f"循环: {batt['cycle_count']} 次")
        print(f"健康度: {batt['health']}")
        print(f"温度: {batt['temperature_c']}°C")
        print(f"电压: {batt['voltage_mv']}mV")
        print(f"电流: {batt['current_ma']}mA")
        print(f"充放电: {batt['charge_state']}")
        print(f"状态: {batt['status']}")
        print(f"激活: {batt['activate']}")


def cmd_qi2_status(args):
    with XiaomiPowerBank(debug=args.debug) as pb:
        if not pb.connect():
            return
        pb.handshake()
        qi2 = pb.get_qi2_status()
        if qi2.get("error"):
            print(f"查询失败: {qi2['error']}")
            return
        print(f"Qi2.2: {qi2['status_text']}")


def cmd_qi2_enable(args):
    with XiaomiPowerBank(debug=args.debug) as pb:
        if not pb.connect():
            return
        pb.handshake()
        qi2 = pb.get_qi2_status()
        if qi2.get("enabled", False):
            print("Qi2.2 已经开启")
            return
        result = pb.set_qi2(True)
        if result.get("error"):
            print(f"开启失败: {result['error']}")
        elif result.get("success"):
            print("Qi2.2 开启成功！")
        else:
            print(f"Qi2.2 开启失败: {result.get('description', '?')}")


def cmd_qi2_disable(args):
    with XiaomiPowerBank(debug=args.debug) as pb:
        if not pb.connect():
            return
        pb.handshake()
        qi2 = pb.get_qi2_status()
        if not qi2.get("enabled", False):
            print("Qi2.2 未开启，无需关闭")
            return
        result = pb.set_qi2(False)
        if result.get("error"):
            print(f"关闭失败: {result['error']}")
        elif result.get("success"):
            print("Qi2.2 关闭成功！")
        else:
            print(f"Qi2.2 关闭失败: {result.get('description', '?')}")


def cmd_raw(args):
    """发送原始十六进制命令"""
    hex_str = args.hex.replace(" ", "").replace("0x", "").replace("0X", "")
    try:
        data = bytes.fromhex(hex_str)
    except ValueError:
        print("无效的十六进制字符串", file=sys.stderr)
        return
    with XiaomiPowerBank(debug=args.debug) as pb:
        if not pb.connect():
            return
        pb.handshake()
        frame = data.ljust(FRAME_SIZE, b'\x00')
        if len(frame) > FRAME_SIZE:
            frame = frame[:FRAME_SIZE]
        result = pb.send_and_wait(frame, timeout=args.timeout)
        if result.get("error"):
            print(f"错误: {result['error']}")
        else:
            print(f"命令: 0x{result['cmd']:02X}")
            print(f"负载: {result['payload'].hex()}")
            print(f"CRC: {'通过' if result['crc_ok'] else '失败'}")
            if args.verbose:
                print(f"原始: {result.get('_raw', result)}")


def main():
    parser = argparse.ArgumentParser(
        description="小米充电宝 USB HID 配置工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python xiaomi_pb.py list              # 列出设备
  python xiaomi_pb.py info              # 显示基本信息
  python xiaomi_pb.py info --full       # 显示全部信息
  python xiaomi_pb.py battery           # 电池信息
  python xiaomi_pb.py qi2-status        # 查询 Qi2.2 状态
  python xiaomi_pb.py qi2-enable        # 开启 Qi2.2
  python xiaomi_pb.py qi2-disable       # 关闭 Qi2.2
        """
    )
    parser.add_argument("--debug", action="store_true", help="显示 HID 通信日志")

    sub = parser.add_subparsers(dest="command")

    p_list = sub.add_parser("list", help="列出已连接的充电宝设备")

    p_info = sub.add_parser("info", help="显示设备信息")
    p_info.add_argument("--full", "-f", action="store_true", help="显示全部信息")

    p_batt = sub.add_parser("battery", help="获取电池信息")

    p_qi2s = sub.add_parser("qi2-status", help="查询 Qi2.2 状态")

    p_qi2e = sub.add_parser("qi2-enable", help="开启 Qi2.2")
    p_qi2d = sub.add_parser("qi2-disable", help="关闭 Qi2.2")

    p_raw = sub.add_parser("raw", help="发送原始十六进制命令")
    p_raw.add_argument("hex", help="十六进制数据 (如 A5060100C8)")
    p_raw.add_argument("--timeout", "-t", type=int, default=3000, help="超时毫秒")
    p_raw.add_argument("--verbose", "-v", action="store_true", help="显示详细输出")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    command_map = {
        "list": cmd_list,
        "info": cmd_info,
        "battery": cmd_battery,
        "qi2-status": cmd_qi2_status,
        "qi2-enable": cmd_qi2_enable,
        "qi2-disable": cmd_qi2_disable,
        "raw": cmd_raw,
    }
    command_map[args.command](args)


if __name__ == "__main__":
    main()
