"""OCR using RapidOCR (ONNX, ~20MB total). Provides a simple sync API.

The RapidOCR runtime is thread-safe per-instance but model files are large,
so we load ONE recognizer per process and let multiple threads call it.
"""

from __future__ import annotations

import io
import threading
from dataclasses import dataclass

from PIL import Image
from rapidocr_onnxruntime import RapidOCR

import onnxruntime
# Silence ONNX Runtime's harmless device-discovery warnings (e.g. the
# "Skipping pci_bus_id" line it emits under WSL2).  3 = ERROR and above only.
onnxruntime.set_default_logger_severity(3)

_lock = threading.Lock()
_engine: RapidOCR | None = None


def _get_engine() -> RapidOCR:
    global _engine
    if _engine is None:
        with _lock:
            if _engine is None:
                _engine = RapidOCR()
    return _engine


@dataclass
class OCRBlock:
    text: str
    confidence: float
    box: list


def ocr_image(image_bytes: bytes) -> list[OCRBlock]:
    """Run OCR on raw image bytes. Returns list of recognized blocks.

    Returns [] on any decode/engine failure (never raises for normal failures).
    """
    try:
        img = Image.open(io.BytesIO(image_bytes))
        if img.mode != "RGB":
            img = img.convert("RGB")
        import numpy as np
        arr = np.array(img)
    except Exception as e:
        print(f"[OCR] image decode failed: {type(e).__name__}: {e}")
        return []

    engine = _get_engine()
    try:
        result, _elapsed = engine(arr)
    except Exception as e:
        print(f"[OCR] engine call failed: {type(e).__name__}: {e}")
        return []

    if not result:
        return []

    blocks = []
    for item in result:
        if len(item) < 3:
            continue
        box, text, score = item[0], item[1], float(item[2])
        if not text or not text.strip():
            continue
        blocks.append(OCRBlock(text=text.strip(), confidence=score, box=box))
    return blocks


def ocr_image_text(image_bytes: bytes) -> str:
    """Convenience: OCR an image and return all recognized text joined by newlines."""
    blocks = ocr_image(image_bytes)
    return "\n".join(b.text for b in blocks)
