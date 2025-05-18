#!/bin/bash

# Nama venv-nya
VENV_DIR="venv"

# Cek kalau venv sudah ada
if [ -d "$VENV_DIR" ]; then
    echo "[*] Virtual environment '$VENV_DIR' sudah ada, memakai yang ini."
else
    echo "[*] Membuat virtual environment di '$VENV_DIR'..."
    python3 -m venv "$VENV_DIR"
fi

echo "[*] Mengaktifkan virtual environment..."
source "$VENV_DIR/bin/activate"

echo "[*] Memperbarui pip..."
pip install --upgrade pip

echo "[*] Menginstall dependencies dari requirements.txt..."
pip install -r requirements.txt

echo "[*] Semua selesai. Untuk menjalankan script, aktifkan venv dengan:"
echo "  source $VENV_DIR/bin/activate"
echo "Lalu jalankan:"
echo "  python blue.py scan"
