import sys
import leechcorepyc

# ================== PyQt5 图形界面集成 ==================
import sys as _sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QTextEdit, QLineEdit, QLabel, QVBoxLayout, QWidget, QHBoxLayout, QComboBox
)
from PyQt5.QtCore import QThread, pyqtSignal

class LeechCoreManager:
    def __init__(self, device="fpga"):
        self.lc = None
        self.device = device
        self.connect()
    def connect(self):
        if self.lc is None:
            self.lc = leechcorepyc.LeechCore(self.device)
    def read(self, addr, size):
        return self.lc.read(addr, size)
    def write(self, addr, data):
        return self.lc.write(addr, data)
    def close(self):
        if self.lc:
            self.lc.close()
            self.lc = None

class ReadWorker(QThread):
    result = pyqtSignal(bytes)
    error = pyqtSignal(str)
    def __init__(self, lc_mgr, addr, size):
        super().__init__()
        self.lc_mgr = lc_mgr
        self.addr = addr
        self.size = size
    def run(self):
        try:
            data = self.lc_mgr.read(self.addr, self.size)
            self.result.emit(data)
        except Exception as e:
            self.error.emit(str(e))

class WriteWorker(QThread):
    result = pyqtSignal(bool)
    error = pyqtSignal(str)
    def __init__(self, lc_mgr, addr, data):
        super().__init__()
        self.lc_mgr = lc_mgr
        self.addr = addr
        self.data = data
    def run(self):
        try:
            self.lc_mgr.write(self.addr, self.data)
            self.result.emit(True)
        except Exception as e:
            self.error.emit(str(e))

class SearchWorker(QThread):
    result = pyqtSignal(list)
    error = pyqtSignal(str)
    def __init__(self, lc_mgr, start_addr, end_addr, pattern):
        super().__init__()
        self.lc_mgr = lc_mgr
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.pattern = pattern
    def run(self):
        try:
            size = self.end_addr - self.start_addr
            chunk_size = 1024*1024
            found = []
            offset = 0
            while offset < size:
                read_size = min(chunk_size, size - offset)
                data = self.lc_mgr.read(self.start_addr + offset, read_size)
                idx = 0
                while True:
                    pos = data.find(self.pattern, idx)
                    if pos == -1:
                        break
                    found.append(self.start_addr + offset + pos)
                    idx = pos + 1
                offset += read_size
            self.result.emit(found)
        except Exception as e:
            self.error.emit(str(e))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.lc_mgr = LeechCoreManager()
        self.display_endian = 'big'  # 'big' or 'little'
        self.write_endian = 'big'    # 'big' or 'little'
        self.init_ui()
    def init_ui(self):
        self.setWindowTitle("DMA 内存读写工具 (该软件可供任何人改编使用 吃水勿忘挖井人-陈主任)")
        # 读
        self.addr_input = QLineEdit("0x00000000")
        self.addr_endian_btn = QPushButton("切换端序")
        self.addr_endian_btn.clicked.connect(lambda: self.toggle_endian(self.addr_input))
        self.size_input = QLineEdit("256")
        self.read_btn = QPushButton("读取内存")
        # 写
        self.write_addr_input = QLineEdit("0x00000000")
        self.write_addr_endian_btn = QPushButton("切换端序")
        self.write_addr_endian_btn.clicked.connect(lambda: self.toggle_endian(self.write_addr_input))
        self.write_data_input = QLineEdit("")
        self.write_data_endian_btn = QPushButton("切换端序")
        self.write_data_endian_btn.clicked.connect(lambda: self.toggle_endian(self.write_data_input))
        self.write_btn = QPushButton("写入内存")
        self.write_endian_combo = QComboBox()
        self.write_endian_combo.addItems(["大端写入", "小端写入"])
        self.write_endian_combo.currentIndexChanged.connect(self.set_write_endian)
        # 搜索
        self.search_start_input = QLineEdit("0x00000000")
        self.search_end_input = QLineEdit("0x00100000")
        self.search_pattern_input = QLineEdit("")
        self.search_btn = QPushButton("搜索内存")
        # 大小端转换
        self.endian_btn = QPushButton("大小端转换")
        self.endian_btn.clicked.connect(self.convert_endian)
        # 显示区
        self.display_endian_combo = QComboBox()
        self.display_endian_combo.addItems(["大端显示", "小端显示"])
        self.display_endian_combo.currentIndexChanged.connect(self.set_display_endian)
        self.mem_view = QTextEdit()
        self.mem_view.setReadOnly(True)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        # 连接信号
        self.read_btn.clicked.connect(self.read_memory)
        self.write_btn.clicked.connect(self.write_memory)
        self.search_btn.clicked.connect(self.search_memory)
        # 布局
        layout = QVBoxLayout()
        # 读布局
        addr_layout = QHBoxLayout()
        addr_layout.addWidget(QLabel("读地址:"))
        addr_layout.addWidget(self.addr_input)
        addr_layout.addWidget(self.addr_endian_btn)
        addr_layout.addWidget(QLabel("长度:"))
        addr_layout.addWidget(self.size_input)
        addr_layout.addWidget(self.read_btn)
        layout.addLayout(addr_layout)
        # 写布局
        write_layout = QHBoxLayout()
        write_layout.addWidget(QLabel("写地址:"))
        write_layout.addWidget(self.write_addr_input)
        write_layout.addWidget(self.write_addr_endian_btn)
        write_layout.addWidget(QLabel("数据(HEX):"))
        write_layout.addWidget(self.write_data_input)
        write_layout.addWidget(self.write_data_endian_btn)
        write_layout.addWidget(self.write_btn)
        write_layout.addWidget(self.write_endian_combo)
        layout.addLayout(write_layout)
        # 搜索布局
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("搜索起始:"))
        search_layout.addWidget(self.search_start_input)
        search_layout.addWidget(QLabel("结束:"))
        search_layout.addWidget(self.search_end_input)
        search_layout.addWidget(QLabel("特征(HEX):"))
        search_layout.addWidget(self.search_pattern_input)
        search_layout.addWidget(self.search_btn)
        layout.addLayout(search_layout)
        # 大小端按钮
        layout.addWidget(self.endian_btn)
        # 显示区
        display_layout = QHBoxLayout()
        display_layout.addWidget(QLabel("内存内容 (十六进制):"))
        display_layout.addWidget(self.display_endian_combo)
        layout.addLayout(display_layout)
        layout.addWidget(self.mem_view)
        layout.addWidget(QLabel("日志:"))
        layout.addWidget(self.log_view)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
    def set_display_endian(self, idx):
        self.display_endian = 'big' if idx == 0 else 'little'
        # 重新渲染内存内容
        text = self.mem_view.toPlainText()
        if text:
            self.display_memory(self.last_read_data if hasattr(self, 'last_read_data') else b'')
    def set_write_endian(self, idx):
        self.write_endian = 'big' if idx == 0 else 'little'
    def toggle_endian(self, lineedit):
        txt = lineedit.text().replace(' ', '')
        prefix = ''
        if txt.lower().startswith('0x'):
            prefix = '0x'
            txt = txt[2:]
        if len(txt) == 0 or len(txt) % 2 != 0:
            self.log_view.append("内容必须为偶数长度的十六进制字符串")
            return
        try:
            b = bytes.fromhex(txt)
            lineedit.setText(prefix + b[::-1].hex().upper())
        except Exception as e:
            self.log_view.append(f"端序切换失败: {e}")
    def read_memory(self):
        try:
            addr = int(self.addr_input.text(), 16)
            size = int(self.size_input.text())
            if size <= 0 or size > 0x100000:
                self.log_view.append("长度必须在1-1048576之间")
                return
            self.read_btn.setEnabled(False)
            self.worker = ReadWorker(self.lc_mgr, addr, size)
            self.worker.result.connect(self.display_memory)
            self.worker.error.connect(self.display_error)
            self.worker.finished.connect(lambda: self.read_btn.setEnabled(True))
            self.worker.start()
            self.log_view.append(f"开始读取: 地址=0x{addr:X}, 长度={size}")
        except Exception as e:
            self.log_view.append(f"输入错误: {e}")
    def display_memory(self, data):
        self.last_read_data = data
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            if self.display_endian == 'little':
                # 每4字节分组翻转，仅影响显示区，直接翻转会导致读取错误
                chunk = b''.join([chunk[j:j+4][::-1] for j in range(0, len(chunk), 4)])
            hex_part = ' '.join(f"{b:02X}" for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f"{i:08X}: {hex_part:<48} {ascii_part}")
        self.mem_view.setText('\n'.join(lines))
        self.log_view.append(f"读取成功, 字节数: {len(data)}")
    def write_memory(self):
        try:
            addr = int(self.write_addr_input.text(), 16)
            hexstr = self.write_data_input.text().replace(' ','')
            if len(hexstr) == 0 or len(hexstr) % 2 != 0:
                self.log_view.append("写入数据必须为偶数长度的十六进制字符串")
                return
            data = bytes.fromhex(hexstr)
            if self.write_endian == 'little':
                data = data[::-1]
            self.write_btn.setEnabled(False)
            self.w_worker = WriteWorker(self.lc_mgr, addr, data)
            self.w_worker.result.connect(self.display_write_result)
            self.w_worker.error.connect(self.display_error)
            self.w_worker.finished.connect(lambda: self.write_btn.setEnabled(True))
            self.w_worker.start()
            self.log_view.append(f"开始写入: 地址=0x{addr:X}, 字节数={len(data)}，端序: {self.write_endian}")
        except Exception as e:
            self.log_view.append(f"写入输入错误: {e}")
    def display_write_result(self, ok):
        if ok:
            self.log_view.append("写入成功")
        else:
            self.log_view.append("写入失败")
    def search_memory(self):
        try:
            start_addr = int(self.search_start_input.text(), 16)
            end_addr = int(self.search_end_input.text(), 16)
            pattern_hex = self.search_pattern_input.text().replace(' ','')
            if end_addr <= start_addr:
                self.log_view.append("结束地址必须大于起始地址")
                return
            if len(pattern_hex) == 0 or len(pattern_hex) % 2 != 0:
                self.log_view.append("特征必须为偶数长度的十六进制字符串")
                return
            pattern = bytes.fromhex(pattern_hex)
            self.search_btn.setEnabled(False)
            self.s_worker = SearchWorker(self.lc_mgr, start_addr, end_addr, pattern)
            self.s_worker.result.connect(self.display_search_result)
            self.s_worker.error.connect(self.display_error)
            self.s_worker.finished.connect(lambda: self.search_btn.setEnabled(True))
            self.s_worker.start()
            self.log_view.append(f"开始搜索: 范围=0x{start_addr:X}-0x{end_addr:X}, 特征={pattern_hex}")
        except Exception as e:
            self.log_view.append(f"搜索输入错误: {e}")
    def display_search_result(self, found):
        if found:
            self.log_view.append(f"找到 {len(found)} 处匹配:")
            for addr in found[:20]:
                self.log_view.append(f"  0x{addr:X}")
            if len(found) > 20:
                self.log_view.append(f"  ... 共{len(found)}处，仅显示前20个")
        else:
            self.log_view.append("未找到匹配")
    def display_error(self, msg):
        self.log_view.append(f"操作失败: {msg}")
    def convert_endian(self):
        cursor = self.mem_view.textCursor()
        selected = cursor.selectedText().replace(' ', '').replace('\n', '').replace('\r', '')
        if not selected:
            self.log_view.append("请先在内存内容区选中一段十六进制字符串")
            return
        try:
            if len(selected) % 8 != 0:
                self.log_view.append("选中内容长度必须为4字节（8位十六进制）整数倍")
                return
            b = bytes.fromhex(selected)
            # 每4字节分组翻转
            little = b''
            for i in range(0, len(b), 4):
                little += b[i:i+4][::-1]
            little_hex = little.hex().upper()
            big_hex = b.hex().upper()
            self.log_view.append(f"原始(大端): {big_hex}")
            self.log_view.append(f"小端(每4字节翻转): {little_hex}")
        except Exception as e:
            self.log_view.append(f"大小端转换失败: {e}")
    def closeEvent(self, event):
        self.lc_mgr.close()
        event.accept()

# ========== 修改main入口，支持gui参数启动图形界面 ==========
def _main_with_gui():
    app = QApplication(_sys.argv)
    win = MainWindow()
    win.show()
    _sys.exit(app.exec_())

if __name__ == "__main__":
    _main_with_gui()
