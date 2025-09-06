import sys
import os
import io
import webbrowser
import requests
import threading
import base64
from PyQt5.QtCore import QEvent
from PyQt5.QtWidgets import QListWidgetItem
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from pyzbar.pyzbar import decode as zbar_decode
from PyQt5.QtWidgets import QStatusBar

# --- Placeholders for your actual API keys ---
VIRUSTOTAL_API_KEY = "992087fb9fa41c08ef7faddc68b62dd875b72c9875c4d98bc8cf5a9cda7d5bae"
ABUSEIPDB_API_KEY = "d36bc8fb11ce7d1520fde741f2b447164afe0b04946ab8c7991789b40434c749e87371dfce77f7cf"

import cv2
import numpy as np
import qrcode
from PIL import ImageQt, Image
from qrcode.image.pil import PilImage

from PyQt5.QtCore import Qt, QTimer, QSize
from PyQt5.QtGui import QPixmap, QImage
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton, QFileDialog,
    QVBoxLayout, QHBoxLayout, QListWidget, QLineEdit, QTableWidget, QTableWidgetItem,
    QMessageBox, QSplitter, QAction, QToolBar, QStyle, QCheckBox
)

def cvimg_to_qpixmap(img_bgr):
    if img_bgr is None:
        return QPixmap()
    img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
    h, w, ch = img_rgb.shape
    bytes_per_line = ch * w
    qimg = QImage(img_rgb.data, w, h, bytes_per_line, QImage.Format_RGB888)
    return QPixmap.fromImage(qimg)

def read_image_from_path(path: str):
    try:
        pil_img = Image.open(path).convert("RGB")
        open_cv_image = np.array(pil_img)
        img = cv2.cvtColor(open_cv_image, cv2.COLOR_RGB2BGR)
        return img
    except Exception as e:
        print("Error reading image:", e)
        return None

def qimage_from_clipboard():
    cb = QApplication.clipboard()
    if cb.mimeData().hasImage():
        qimg = cb.image()
        if not qimg.isNull():
            return qimg
    return None

def cvimg_from_qimage(qimg: QImage):
    qimg = qimg.convertToFormat(QImage.Format_RGBA8888)
    w, h = qimg.width(), qimg.height()
    ptr = qimg.bits()
    ptr.setsize(qimg.sizeInBytes())
    arr = np.array(ptr, dtype=np.uint8).reshape((h, w, 4))
    return cv2.cvtColor(arr, cv2.COLOR_RGBA2BGR)

def _save_qr_as_png(self):
    if self.qr_display.pixmap() is None:
        QMessageBox.warning(self, "No QR Preview", "No generated QR code available to save.")
        return

    save_path, _ = QFileDialog.getSaveFileName(
        self, "Save QR Code", "qr_output.png", "PNG Image (*.png)"
    )
    if save_path:
        try:
            pixmap = self.qr_display.pixmap()
            if pixmap:
                image = pixmap.toImage()
                image.save(save_path)
                self._update_status(f"QR Code saved to {save_path}", color="green")
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save QR Code:\n{str(e)}")
                
def _update_status(self, text, color="black"):
    def update():
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {color}")
    QApplication.instance().postEvent(self.status_label, QEvent(QEvent.User))
    self.status_label.setText(text)
    self.status_label.setStyleSheet(f"color: {color}")

def _set_item_color(self, item, verdict, color):
    def update():
        item.setText(f"{item.text()} [{verdict}]")
        item.setForeground(Qt.red if color == "red" else Qt.green if color == "green" else Qt.black)
    QApplication.instance().postEvent(item.listWidget(), QEvent(QEvent.User))
    item.setText(f"{item.text()} [{verdict}]")
    item.setForeground(Qt.red if color == "red" else Qt.green if color == "green" else Qt.black)
    

# --- Add color-coded entry and malicious checking ---
# def check_url_malicious_async(main_window, url, list_item):
#     def worker():
#         verdict = "unknown"
        
#         # VirusTotal Check
#         try:
#             vt_url = f"https://www.virustotal.com/api/v3/urls"
#             url_id = requests.post(vt_url, headers={"x-apikey": VIRUSTOTAL_API_KEY}, data={"url": url})
#             if url_id.ok:
#                 scan_id = url_id.json()["data"]["id"]
#                 vt_result = requests.get(f"{vt_url}/{scan_id}", headers={"x-apikey": VIRUSTOTAL_API_KEY})
#                 if vt_result.ok:
#                     stats = vt_result.json()["data"]["attributes"]["last_analysis_stats"]
#                     if stats.get("malicious", 0) > 0:
#                         verdict = "malicious"
#                     else:
#                         verdict = "safe"
#         except Exception as e:
#             print("VirusTotal check error:", e)
                
#         # AbuseIPDB Check (only for IPs or domains)
#         try:
#             host = urlparse(url).netloc
#             ip_lookup = f"https://api.abuseipdb.com/api/v2/check?ipAddress={host}&maxAgeInDays=90"
#             headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
#             resp = requests.get(ip_lookup, headers=headers)
#             if resp.ok:
#                 abuse_score = resp.json()["data"]["abuseConfidenceScore"]
#                 if abuse_score >= 50:
#                     verdict = "malicious"
#                 elif verdict != "malicious":
#                     verdict = "safe"
#         except Exception as e:
#             print("AbuseIPDB check error:", e)
                
#         # Update UI in main thread
#         def update_ui():
#             if verdict == "malicious":
#                 list_item.setText(f"\U0001F534 {url}") # 🔴
#                 list_item.setForeground(Qt.red)
#                 main_window.statusBar().showMessage(f"{url} flagged as MALICIOUS", 4000)
#             elif verdict == "safe":
#                 list_item.setText(f"\U0001F7E2 {url}") # 🟢
#                 list_item.setForeground(Qt.darkGreen)
#                 main_window.statusBar().showMessage(f"{url} looks SAFE", 2000)
#             else:
#                 list_item.setForeground(Qt.black)
                    
#         main_window.statusBar().showMessage(f"Checking {url} for malicious behavior…")
#         main_window.statusBar().repaint()
#         QTimer.singleShot(0, update_ui)
            
#     threading.Thread(target=worker, daemon=True).start()

class QRUrlExtractor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QR → URL Extractor")
        self.resize(1100, 700)

        self.detector = cv2.QRCodeDetector()
        self.current_img = None
        self.video = None
        self.frame_timer = QTimer(self)
        self.frame_timer.timeout.connect(self._grab_frame)
        self.decode_every_n = 5
        self._frame_count = 0

        self._build_ui()
        self._build_toolbar()
        self.setAcceptDrops(True)
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

    def _build_ui(self):
        central = QWidget(self)
        self.setCentralWidget(central)

        self.preview = QLabel("Drop an image, Open a file, Paste from clipboard, or Start Webcam")
        self.preview.setAlignment(Qt.AlignCenter)
        self.preview.setStyleSheet("QLabel{background:#111;color:#bbb;border:1px solid #333}")
        self.preview.setMinimumSize(400, 300)

        self.decoded_list = QListWidget()
        self.decoded_list.itemSelectionChanged.connect(self._on_select_decoded)

        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("Decoded URL or text will appear here… (editable)")

        self.parse_btn = QPushButton("Parse params")
        self.parse_btn.clicked.connect(self._parse_params)

        self.params_table = QTableWidget(0, 2)
        self.params_table.setHorizontalHeaderLabels(["Key", "Value"])
        self.params_table.horizontalHeader().setStretchLastSection(True)

        self.add_row_btn = QPushButton("+ Param")
        self.add_row_btn.clicked.connect(self._add_param_row)
        self.rebuild_btn = QPushButton("Rebuild URL & Update QR")
        self.rebuild_btn.clicked.connect(self._rebuild_url)

        self.copy_btn = QPushButton("Copy")
        self.copy_btn.clicked.connect(self._copy_url)
        self.open_btn = QPushButton("Open in browser")
        self.open_btn.clicked.connect(self._open_in_browser)

        self.autostop_cb = QCheckBox("Auto-stop webcam when a QR is found")
        self.autostop_cb.setChecked(True)

        self.qr_display = QLabel("QR Code will appear here")
        self.qr_display.setAlignment(Qt.AlignCenter)
        self.qr_display.setStyleSheet("QLabel{background:#fff;border:1px solid #888}")
        self.qr_display.setFixedHeight(200)

        right_col = QVBoxLayout()
        right_col.addWidget(QLabel("Decoded results"))
        right_col.addWidget(self.decoded_list, 2)
        right_col.addWidget(QLabel("URL / Text"))
        right_col.addWidget(self.url_edit)
        right_col.addWidget(self.parse_btn)
        right_col.addWidget(QLabel("Query parameters"))
        right_col.addWidget(self.params_table, 3)

        btns = QHBoxLayout()
        btns.addWidget(self.add_row_btn)
        btns.addWidget(self.rebuild_btn)
        btns.addStretch(1)
        btns.addWidget(self.copy_btn)
        btns.addWidget(self.open_btn)
        right_col.addLayout(btns)
        right_col.addWidget(self.qr_display)
        right_col.addWidget(self.autostop_cb)
        
        self.status_label = QLabel("Status: Ready")
        self.status_label.setStyleSheet("color: gray; font-weight: bold; padding: 4px;")
        right_col.addWidget(self.status_label)
        
        # Obfuscation toggles + button
        obf_layout = QHBoxLayout()
        self.obf_base64_cb = QCheckBox("Base64 Encode")
        self.obf_base64_cb.setChecked(True)

        self.obfuscate_btn = QPushButton("Obfuscate this QR")
        self.obfuscate_btn.clicked.connect(self._obfuscate_qr)

        obf_layout.addWidget(self.obf_base64_cb)
        obf_layout.addWidget(self.obfuscate_btn)
        right_col.addLayout(obf_layout)

        right = QWidget()
        right.setLayout(right_col)

        splitter = QSplitter()
        splitter.addWidget(self.preview)
        splitter.addWidget(right)
        splitter.setSizes([600, 500])

        layout = QVBoxLayout(central)
        layout.addWidget(splitter)

    def _build_toolbar(self):
        tb = QToolBar("Main")
        tb.setIconSize(QSize(18, 18))
        self.addToolBar(tb)

        act_open = QAction(self.style().standardIcon(QStyle.SP_DialogOpenButton), "Open Image", self)
        act_open.triggered.connect(self.open_image)
        tb.addAction(act_open)

        act_clip = QAction(self.style().standardIcon(QStyle.SP_DialogYesButton), "Paste Image", self)
        act_clip.triggered.connect(self.paste_image)
        tb.addAction(act_clip)

        self.act_cam = QAction(self.style().standardIcon(QStyle.SP_ComputerIcon), "Start Webcam", self)
        self.act_cam.setCheckable(True)
        self.act_cam.triggered.connect(self.toggle_webcam)
        tb.addAction(self.act_cam)

        tb.addSeparator()
        act_clear = QAction(self.style().standardIcon(QStyle.SP_TrashIcon), "Clear", self)
        act_clear.triggered.connect(self._clear_all)
        tb.addAction(act_clear)
        
        save_btn = QAction("Save QR as PNG", self)
        save_btn = QAction(self.style().standardIcon(QStyle.SP_DialogSaveButton), "Save QR", self)
        save_btn.triggered.connect(self._save_qr_as_png)
        tb.addAction(save_btn)

    def open_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open image", "", "Images (*.png *.jpg *.jpeg *.bmp *.webp)")
        if not path:
            return
        img = read_image_from_path(path)
        if img is None:
            QMessageBox.warning(self, "Error", "Could not open the image.")
            return
        self._set_image(img)
        self._decode_current()

    def paste_image(self):
        qimg = qimage_from_clipboard()
        if qimg is None:
            QMessageBox.information(self, "Clipboard", "Clipboard does not contain an image.")
            return
        img = cvimg_from_qimage(qimg)
        self._set_image(img)
        self._decode_current()

    def toggle_webcam(self, checked):
        if checked:
            self.video = cv2.VideoCapture(0)
            if not self.video.isOpened():
                self.video = None
                self.act_cam.setChecked(False)
                QMessageBox.warning(self, "Webcam", "Could not open default camera.")
                return
            self._frame_count = 0
            self.frame_timer.start(30)
            self.act_cam.setText("Stop Webcam")
        else:
            self.frame_timer.stop()
            if self.video is not None:
                self.video.release()
                self.video = None
            self.act_cam.setText("Start Webcam")

    def _grab_frame(self):
        if self.video is None:
            return
        ok, frame = self.video.read()
        if not ok:
            return
        self.current_img = frame
        self._show_preview(frame)
        self._frame_count += 1
        if self._frame_count % self.decode_every_n == 0:
            decoded = self._decode(frame)
            if decoded:
                self._populate_decoded(decoded)
                if self.autostop_cb.isChecked():
                    self.toggle_webcam(False)

    def _clear_all(self):
        self.preview.setText("Drop an image, Open a file, Paste from clipboard, or Start Webcam")
        self.current_img = None
        self.decoded_list.clear()
        self.url_edit.clear()
        self.params_table.setRowCount(0)
        self.qr_display.clear()
        self._update_status("", color="black")

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            for u in event.mimeData().urls():
                if u.toLocalFile().lower().endswith((".png", ".jpg", ".jpeg", ".bmp", ".webp")):
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dropEvent(self, event):
        for u in event.mimeData().urls():
            path = u.toLocalFile()
            if path.lower().endswith((".png", ".jpg", ".jpeg", ".bmp", ".webp")):
                img = read_image_from_path(path)
                if img is not None:
                    self._set_image(img)
                    self._decode_current()
                    break

    def _set_image(self, img_bgr):
        self.current_img = img_bgr
        self._show_preview(img_bgr)

    def _show_preview(self, img_bgr):
        pix = cvimg_to_qpixmap(img_bgr)
        self.preview.setPixmap(pix.scaled(self.preview.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation))

    def _decode_current(self):
        if self.current_img is None:
            return
        decoded = self._decode(self.current_img)
        self._populate_decoded(decoded)

    def _decode(self, img_bgr):
        decoded_texts = []
        try:
            # Resize large images for faster processing
            h, w = img_bgr.shape[:2]
            if max(h, w) > 1600:
                scale = 1600.0 / max(h, w)
                img_bgr = cv2.resize(img_bgr, (int(w * scale), int(h * scale)))

            # Convert to grayscale
            gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)

            # --- Method 1: pyzbar (highly accurate) ---
            barcodes = zbar_decode(gray)
            for barcode in barcodes:
                text = barcode.data.decode("utf-8")
                if text:
                    decoded_texts.append(text)

            # --- Method 2: fallback to OpenCV QRCodeDetector ---
            if not decoded_texts:
                try:
                    retval, decoded_info, points, _ = self.detector.detectAndDecodeMulti(gray)
                    if retval:
                        decoded_texts.extend([t for t in decoded_info if t])
                    else:
                        # fallback to single QR detection
                        t, pts = self.detector.detectAndDecode(gray)
                        if t:
                            decoded_texts.append(t)
                except Exception as inner_e:
                    print("[Fallback Decode Error]:", inner_e)

        except Exception as e:
            print("[Decode Error]:", e)

        return decoded_texts

    def _populate_decoded(self, decoded_list):
        if not decoded_list:
            QMessageBox.information(self, "QR", "No QR codes decoded.")
            return
        self.decoded_list.clear()
        seen = set()
        for t in decoded_list:
            if t not in seen:
                item = QListWidgetItem(t)
                self.decoded_list.addItem(item)
                #check_url_malicious_async(self, t, item)
                seen.add(t)
        if self.decoded_list.count() > 0:
            self.decoded_list.setCurrentRow(0)
            
            
    # def _display_verdict(self, verdict_text, is_malicious=False):
    #     verdict_label = QLabel(verdict_text)
    #     verdict_label.setWordWrap(True)
    #     color = 'red' if is_malicious else 'green'
    #     verdict_label.setStyleSheet(f'color: {color}; font-weight: bold')
    #     self.verdict_layout.addWidget(verdict_label)
    #     self.statusBar().showMessage(verdict_text)


    def _on_select_decoded(self):
        items = self.decoded_list.selectedItems()
        if not items:
            return
        text = items[0].text()
        self.url_edit.setText(text)
        self._parse_params()
        self._generate_qrcode(text)

    def _parse_params(self):
        url = self.url_edit.text().strip()
        self.params_table.setRowCount(0)
        if not url:
            return
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return
        params = parse_qsl(parsed.query, keep_blank_values=True)
        self.params_table.setRowCount(len(params))
        for r, (k, v) in enumerate(params):
            self.params_table.setItem(r, 0, QTableWidgetItem(k))
            self.params_table.setItem(r, 1, QTableWidgetItem(v))

    def _add_param_row(self):
        r = self.params_table.rowCount()
        self.params_table.insertRow(r)
        self.params_table.setItem(r, 0, QTableWidgetItem(""))
        self.params_table.setItem(r, 1, QTableWidgetItem(""))

    def _rebuild_url(self):
        url = self.url_edit.text().strip()
        if not url:
            return
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            return
        rows = self.params_table.rowCount()
        params = []
        for r in range(rows):
            k_item = self.params_table.item(r, 0)
            v_item = self.params_table.item(r, 1)
            k = (k_item.text() if k_item else "").strip()
            v = (v_item.text() if v_item else "").strip()
            if k != "":
                params.append((k, v))
        new_query = urlencode(params, doseq=True)
        rebuilt = urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))
        self.url_edit.setText(rebuilt)
        self._generate_qrcode(rebuilt)

    def _generate_qrcode(self, data):
        qr = qrcode.QRCode(version=1, box_size=8, border=2)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white", image_factory=PilImage).get_image()

        buffer = io.BytesIO()
        img.save(buffer, "PNG")  # No need for format= keyword
        buffer.seek(0)

        qt_img = QImage()
        qt_img.loadFromData(buffer.read(), "PNG")
        pix = QPixmap.fromImage(qt_img)
        self.qr_display.setPixmap(pix)
        
        # Scale it to a clear 200x200 with smooth transformation
        pix = QPixmap.fromImage(qt_img).scaled(
            200, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation
        )

        # Display in UI
        self.qr_display.setPixmap(pix)


    def _copy_url(self):
        QApplication.clipboard().setText(self.url_edit.text())
        self.statusBar().showMessage("Copied to clipboard", 2000)

    def _open_in_browser(self):
        text = self.url_edit.text().strip()
        if not text:
            return
        try:
            webbrowser.open(text)
        except Exception:
            QMessageBox.warning(self, "Browser", "Could not open the URL/text in a browser.")
            
    def _save_qr_as_png(self):
        if self.qr_display.pixmap() is None:
            QMessageBox.warning(self, "No QR Preview", "No generated QR code available to save.")
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save QR Code", "qr_output.png", "PNG Image (*.png)"
        )
        if save_path:
            try:
                pixmap = self.qr_display.pixmap()
                if pixmap:
                    image = pixmap.toImage()
                    image.save(save_path)
                    self._update_status(f"QR Code saved to {save_path}", color="green")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Failed to save QR Code:\n{str(e)}")
    def _update_status(self, text, color="black"):
        def update():
            self.status_label.setText(text)
            self.status_label.setStyleSheet(f"color: {color}")
        QApplication.instance().postEvent(self.status_label, QEvent(QEvent.User))
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {color}")

    def _set_item_color(self, item, verdict, color):
        def update():
            item.setText(f"{item.text()} [{verdict}]")
            item.setForeground(Qt.red if color == "red" else Qt.green if color == "green" else Qt.black)
        QApplication.instance().postEvent(item.listWidget(), QEvent(QEvent.User))
        item.setText(f"{item.text()} [{verdict}]")
        item.setForeground(Qt.red if color == "red" else Qt.green if color == "green" else Qt.black)
        
    def _obfuscate_qr(self):
        current_item = self.decoded_list.currentItem()
        if not current_item:
            self._update_status("No QR selected to obfuscate.", "red")
            return

        original_url = current_item.text().split("  [")[0].strip()
        obfuscated_url = original_url
        self._update_status("Starting obfuscation…", "orange")
        
        ############################ To Be UnCommented after testing ###################
        # # Apply Base64 Encoding (without stripping =)
        # if self.obf_base64_cb.isChecked():
        #     try:
        #         obf_bytes = base64.b64encode(obfuscated_url.encode('utf-8'))
        #         obfuscated_url = obf_bytes.decode('utf-8')  # ← Do NOT strip '='
        #         self._update_status(f"Base64 applied ✅ → {obfuscated_url}", "blue")
        #     except Exception as e:
        #         self._update_status(f"Base64 Error: {e}", "red")
        #         return
        
        # Apply Base64 Obfuscation with JSOutProx redirect
        if self.obf_base64_cb.isChecked():
            try:
                original = obfuscated_url  # Save original before encoding
                obf_bytes = base64.b64encode(original.encode("utf-8"))
                encoded = obf_bytes.decode("utf-8")  # Keep padding = characters

                # Create redirect URL via JSOutProx
                obfuscated_url = f"https://jsoutprox.onrender.com?r={encoded}"

                self._update_status(f"Base64 + Redirector applied ✅ → {obfuscated_url}", "blue")
            except Exception as e:
                self._update_status(f"Obfuscation Error: {e}", "red")
                return

        # Update decoded list with obfuscated result
        obf_item = QListWidgetItem(obfuscated_url)
        self.decoded_list.addItem(obf_item)
        self.decoded_list.setCurrentItem(obf_item)

def main():
    app = QApplication(sys.argv)
    w = QRUrlExtractor()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
