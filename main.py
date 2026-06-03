#!/usr/bin/env python3
"""
小米充电宝 USB HID 通信工具

从网页版 (https://powerbank.mieco.net/) 逆向提取的通信协议，
通过 WebHID → Python hidapi 移植。

依赖: pip install hidapi

用法:
  # 无参数进入交互模式
  python xiaomi_pb.py

  # 连接并显示完整信息
  python xiaomi_pb.py info

  # 开启 Qi2.2
  python xiaomi_pb.py qi2-enable

  # 关闭 Qi2.2
  python xiaomi_pb.py qi2-disable

  # 发送原始十六进制命令
  python xiaomi_pb.py raw A5060100C8
"""

import argparse
import functools
import shlex
import struct
import sys
import threading
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
    return full.ljust(FRAME_SIZE, b'\x00')


def build_hello_frame() -> bytes:
    """构建 Hello 握手帧 (特殊格式)"""
    frame = bytearray(FRAME_SIZE)
    frame[0] = HEAD
    frame[1] = CMD_HELLO
    frame[2] = 13
    ts = int(time.time()) + 28800
    struct.pack_into('<I', frame, 3, ts)
    magic = b"xiaomi-pb"
    frame[7:7 + len(magic)] = magic
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
    actual_payload_len = min(payload_len, len(data) - 4)
    payload = data[3:3 + actual_payload_len]
    received_crc = data[3 + actual_payload_len]
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
    series = (cell_config >> 4) & 0x0F
    parallel = cell_config & 0x0F
    cell_count = (1 if series == 0 and cell_config != 0 else series) * (1 if parallel == 0 and cell_config != 0 else parallel)
    level = payload[12]
    temp_raw = payload[13]
    temp = temp_raw if temp_raw < 128 else temp_raw - 256
    voltage = struct.unpack_from('<H', payload, 14)[0]
    current = struct.unpack_from('<H', payload, 16)[0]
    if current > 32767:
        current -= 65536
    return {
        "status": "成功" if status == 0 else f"失败({status})",
        "activate": "已激活" if activate == 1 else "未激活" if activate == 0 else f"保留({activate})",
        "cycle_count": cycle_count,
        "health": battery_health,
        "charge_state": chg_map.get(chg_state, f"未知({chg_state})"),
        "fault_type": fault_type,
        "cell_count": cell_count,
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


def decode_battery_id_response(payload: bytes) -> dict:
    """电池编号响应 (CMD 0x14)"""
    if len(payload) < 2:
        return {"error": "电池编号数据不足"}
    status = payload[0]
    cell_index = payload[1]
    raw_id = ""
    if len(payload) > 2:
        raw_bytes = payload[2:]
        null_pos = raw_bytes.find(b'\x00')
        if null_pos != -1:
            raw_bytes = raw_bytes[:null_pos]
        raw_id = raw_bytes.decode('ascii', errors='replace')
    parsed = {}
    # 解析电池编码 (9位固定格式)
    raw_stripped = raw_id.replace(" ", "")
    if len(raw_stripped) >= 9:
        enterprise = raw_stripped[0:4]
        year_code = raw_stripped[6]
        month_code = raw_stripped[7]
        day_code = raw_stripped[8]
        year_map = {'F': 2025, 'G': 2026, 'H': 2027, 'J': 2028, 'K': 2029,
                    'L': 2030, 'M': 2031, 'N': 2032, 'P': 2033, 'R': 2034,
                    'S': 2035, 'T': 2036, 'V': 2037}
        month_map = {'1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6,
                     '7': 7, '8': 8, '9': 9, 'A': 10, 'B': 11, 'C': 12}
        day_map = {'1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6,
                   '7': 7, '8': 8, '9': 9, 'A': 10, 'B': 11, 'C': 12,
                   'D': 13, 'E': 14, 'F': 15, 'G': 16, 'H': 17, 'J': 18,
                   'K': 19, 'L': 20, 'M': 21, 'N': 22, 'P': 23, 'R': 24,
                   'S': 25, 'T': 26, 'V': 27, 'W': 28, 'X': 29, 'Y': 30,
                   '0': 31}
        year = year_map.get(year_code, f"未知({year_code})")
        month = month_map.get(month_code, f"未知({month_code})")
        day = day_map.get(day_code, f"未知({day_code})")
        if isinstance(year, int) and isinstance(month, int) and isinstance(day, int):
            prod_date = f"{year}-{month:02d}-{day:02d}"
        else:
            prod_date = f"{year}-{month}-{day}"
        parsed = {
            "enterprise_code": enterprise,
            "production_date": prod_date,
        }
    return {
        "status": "成功" if status == 0 else f"失败({status})",
        "cell_index": cell_index,
        "battery_id": raw_id,
        "parsed": parsed,
    }


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


class XiaomiPowerBank:
    """小米充电宝 HID 通信封装"""

    def __init__(self, debug=False):
        self.device = None
        self.debug = debug
        self._heartbeat_running = False
        self._heartbeat_thread = None

    def log(self, msg):
        if self.debug:
            print(f"[HID] {msg}", file=sys.stderr)

    def connect(self, dev_info=None, wait=False):
        if dev_info is None:
            dev_info = find_device()
        while dev_info is None and wait:
            print("没有检测到充电宝。请连续按8次按钮进入数据传输模式，再使用USB线连接到电脑；等待接入……", file=sys.stderr, end="")
            while dev_info is None:
                time.sleep(5)
                print(".", end="", flush=True, file=sys.stderr)
                dev_info = find_device()
            print(file=sys.stderr)
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
        self.stop_heartbeat()
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

    def get_cell_status(self, cell_count=0) -> dict:
        """获取电芯状态"""
        payload = bytes([1, cell_count]) if cell_count > 0 else b""
        frame = build_command_frame(CMD_GET_CELL_STATUS, payload)
        result = self.send_and_wait(frame, expected_cmd=RSP_CELL_STATUS, timeout=3000)
        if result["error"]:
            return result
        info = decode_cell_status(result["payload"])
        info["_raw"] = result
        return info

    def get_battery_id(self, cell_index: int = 1) -> dict:
        """获取电芯电池编号信息"""
        payload = bytes([cell_index])
        frame = build_command_frame(CMD_GET_BATTERY_ID, payload)
        result = self.send_and_wait(frame, expected_cmd=RSP_BATTERY_ID, timeout=1000)
        if result["error"]:
            return result
        info = decode_battery_id_response(result["payload"])
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

    def start_heartbeat(self, interval=15):
        """启动心跳保活线程，定时发送 Hello 保持充电宝在线"""
        if self._heartbeat_running:
            return
        self._heartbeat_running = True
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, args=(interval,), daemon=True
        )
        self._heartbeat_thread.start()
        self.log(f"[Heartbeat] 已启动，间隔 {interval}s")

    def stop_heartbeat(self):
        """停止心跳保活线程"""
        self._heartbeat_running = False
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=2)
            self._heartbeat_thread = None

    def _heartbeat_loop(self, interval):
        """心跳循环"""
        while self._heartbeat_running:
            time.sleep(interval)
            try:
                frame = build_hello_frame()
                self._write(frame)
                if self.debug:
                    self.log("[Heartbeat] 发送 Hello")
            except Exception as e:
                if self.debug:
                    self.log(f"[Heartbeat] 失败: {e}")
                break

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stop_heartbeat()
        if self.device:
            try:
                self.device.close()
            except Exception:
                pass
            self.device = None


# --- use_pb 装饰器 ---

def use_pb(fn):
    """装饰器：让命令函数支持传入预连接 pb 或自动创建新连接。

    在交互模式下传入 pb 复用已有连接；
    在单次执行模式不传 pb，自动创建临时连接。
    """
    @functools.wraps(fn)
    def wrapper(args, pb=None):
        if pb is not None:
            return fn(args, pb)
        with XiaomiPowerBank(debug=args.debug) as device:
            if not device.connect(wait=True):
                return
            return fn(args, device)
    return wrapper


# --- CLI 命令 ---

@use_pb
def cmd_info(args, pb):
    info = pb.handshake()
    if info.get("error"):
        print(f"握手失败: {info['error']}")
        return
    print(f"设备: {info['device_name']} ({info['device_model']})")
    print(f"型号ID: {info['model_id']}")
    print(f"序列号: {info['serial_number']}")
    print(f"充电状态: {info['charging_status']}")
    print()
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
    cell_count = batt.get("cell_count", 0)
    cells = pb.get_cell_status(cell_count=cell_count)
    if "error" not in cells and cells.get("cells"):
        valid_temps = [c for c in cells["cells"] if c['temp_c'] != -127]
        if valid_temps:
            print(f"温度点 ({len(valid_temps)} 个):")
            for c in valid_temps:
                print(f"  #{c['index']}: {c['temp_c']}°C")
        print(f"电芯状态 ({cell_count} 节):")
        for c in cells["cells"]:
            print(f"  #{c['index']}: {c['voltage_mv']}mV  {c['current_ma']}mA")
        print()
    if cell_count > 0:
        print("电芯编号信息:")
        for i in range(1, cell_count + 1):
            bid = pb.get_battery_id(i)
            if bid.get("error"):
                print(f"  #{i}: 查询失败 - {bid['error']}")
            else:
                parts = []
                if bid.get("battery_id"):
                    parts.append(f"编码={bid['battery_id']}")
                if bid.get("parsed", {}).get("production_date"):
                    parts.append(f"生产日期={bid['parsed']['production_date']}")
                if bid.get("parsed", {}).get("enterprise_code"):
                    parts.append(f"厂商代码={bid['parsed']['enterprise_code']}")
                print(f"  #{i}: {'  '.join(parts)}")
        print()
    temp = pb.get_cell_temp_model()
    if "error" not in temp:
        print(f"电芯型号: {temp.get('battery_model', '?')}")
        print(f"温度阈值: {temp['low_temp']}°C ~ {temp['high_temp']}°C")


@use_pb
def cmd_qi2_enable(args, pb):
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


@use_pb
def cmd_qi2_disable(args, pb):
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


@use_pb
def cmd_raw(args, pb):
    """发送原始十六进制命令"""
    hex_str = args.hex.replace(" ", "").replace("0x", "").replace("0X", "")
    try:
        data = bytes.fromhex(hex_str)
    except ValueError:
        print("无效的十六进制字符串", file=sys.stderr)
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


command_map = {
    "info": cmd_info,
    "qi2-enable": cmd_qi2_enable,
    "qi2-disable": cmd_qi2_disable,
    "raw": cmd_raw,
}

INTERACTIVE_COMMANDS = sorted(command_map.keys()) + ["help", "exit"]


def print_interactive_help():
    print("可用命令:")
    print(f"  {'info':20s} 显示全部信息 (电池/Qi2/电芯/温度)")
    print(f"  {'qi2-enable':20s} 开启 Qi2.2")
    print(f"  {'qi2-disable':20s} 关闭 Qi2.2")
    print(f"  {'raw <hex>':20s} 发送原始十六进制命令")
    print(f"  {'help':20s} 显示此帮助")
    print(f"  {'exit':20s} 退出交互模式")
    print()


def interactive_mode(debug):
    """交互式命令行模式：保持设备连接，持续接受用户输入"""
    pb = XiaomiPowerBank(debug=debug)
    if not pb.connect(wait=True):
        return
    info = pb.handshake()
    if info.get("error"):
        print(f"握手失败: {info['error']}")
        pb.disconnect()
        return

    print(f"已连接: {info['device_name']} ({info['device_model']})")
    print(f"序列号: {info['serial_number']}")
    print(f"充电状态: {info['charging_status']}")
    print()

    pb.start_heartbeat(interval=15)
    parser = _build_argparser()

    try:
        while True:
            try:
                line = input("xiaomi-pb> ").strip()
            except EOFError:
                print()
                break

            if not line:
                continue
            if line in ("exit", "quit", "q"):
                break
            if line in ("help", "?"):
                print_interactive_help()
                continue

            try:
                tokens = shlex.split(line)
            except ValueError as e:
                print(f"参数解析错误: {e}")
                continue

            try:
                ns = argparse.Namespace(debug=debug)
                args = parser.parse_args(tokens, namespace=ns)
            except SystemExit:
                continue
            except Exception as e:
                print(f"错误: {e}")
                continue

            fn = command_map.get(args.command)
            if fn:
                try:
                    fn(args, pb=pb)
                except Exception as e:
                    print(f"命令执行失败: {e}")
            else:
                print(f"未知命令: {args.command}")
    except KeyboardInterrupt:
        print("\n正在退出...")
    finally:
        pb.disconnect()
        print("已断开连接。")


def _build_argparser():
    """构建参数解析器（内部复用）"""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--debug", action="store_true")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("info")
    sub.add_parser("qi2-enable")
    sub.add_parser("qi2-disable")
    p_raw = sub.add_parser("raw")
    p_raw.add_argument("hex")
    p_raw.add_argument("--timeout", "-t", type=int, default=3000)
    p_raw.add_argument("--verbose", "-v", action="store_true")

    return parser


def main():
    parser = argparse.ArgumentParser(
        description="小米充电宝 USB HID 配置工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python xiaomi_pb.py                        # 进入交互模式
  python xiaomi_pb.py info                   # 显示全部信息
  python xiaomi_pb.py qi2-enable             # 开启 Qi2.2
  python xiaomi_pb.py qi2-disable            # 关闭 Qi2.2
  python xiaomi_pb.py raw A5060100C8         # 发送原始命令
        """
    )
    parser.add_argument("--debug", action="store_true", help="显示 HID 通信日志")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("info", help="显示全部设备信息")

    p_qi2e = sub.add_parser("qi2-enable", help="开启 Qi2.2")
    p_qi2d = sub.add_parser("qi2-disable", help="关闭 Qi2.2")

    p_raw = sub.add_parser("raw", help="发送原始十六进制命令")
    p_raw.add_argument("hex", help="十六进制数据 (如 A5060100C8)")
    p_raw.add_argument("--timeout", "-t", type=int, default=3000, help="超时毫秒")
    p_raw.add_argument("--verbose", "-v", action="store_true", help="显示详细输出")

    args = parser.parse_args()

    if not args.command:
        interactive_mode(args.debug)
        return

    command_map[args.command](args)


if __name__ == "__main__":
    main()
