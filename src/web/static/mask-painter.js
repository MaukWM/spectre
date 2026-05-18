/**
 * Mask Painter — HTML5 Canvas brush/eraser with undo/redo and zoom.
 *
 * Backing canvas is always 640x480. Display size is scaled by CSS.
 * White = HUD (to remove), Black = preserve.
 * Painted regions shown as semi-transparent red overlay.
 */

const CANVAS_W = 640;
const CANVAS_H = 480;
const MAX_UNDO = 20;

let canvas, ctx;
let bgImage = null;       // reference frame as Image
let tool = 'brush';        // 'brush' | 'eraser'
let brushSize = 20;
let zoom = 1;
let painting = false;
let lastX = 0, lastY = 0;

// Undo/redo stacks of ImageData.
let undoStack = [];
let redoStack = [];

// Offscreen mask canvas (single channel simulation via full canvas).
let maskCanvas, maskCtx;

function initMaskPainter(referenceUrl) {
  canvas = document.getElementById('mask-canvas');
  ctx = canvas.getContext('2d');
  canvas.width = CANVAS_W;
  canvas.height = CANVAS_H;

  // Create offscreen mask canvas.
  maskCanvas = document.createElement('canvas');
  maskCanvas.width = CANVAS_W;
  maskCanvas.height = CANVAS_H;
  maskCtx = maskCanvas.getContext('2d');
  maskCtx.fillStyle = '#000';
  maskCtx.fillRect(0, 0, CANVAS_W, CANVAS_H);

  // Load reference image.
  bgImage = new Image();
  bgImage.crossOrigin = 'anonymous';
  bgImage.onload = () => {
    pushUndo();
    render();
  };
  bgImage.src = referenceUrl;

  // Mouse events.
  canvas.addEventListener('mousedown', onMouseDown);
  canvas.addEventListener('mousemove', onMouseMove);
  canvas.addEventListener('mouseup', onMouseUp);
  canvas.addEventListener('mouseleave', onMouseUp);

  // Touch events.
  canvas.addEventListener('touchstart', onTouchStart, { passive: false });
  canvas.addEventListener('touchmove', onTouchMove, { passive: false });
  canvas.addEventListener('touchend', onMouseUp);

  // Keyboard shortcuts.
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'z') { e.preventDefault(); maskUndo(); }
    if (e.ctrlKey && e.key === 'y') { e.preventDefault(); maskRedo(); }
    if (e.key === 'b') setTool('brush');
    if (e.key === 'e') setTool('eraser');
  });
}

// ── Coordinate conversion ────────────────────────────────────────────── //

function canvasCoords(e) {
  const rect = canvas.getBoundingClientRect();
  return {
    x: (e.clientX - rect.left) * (CANVAS_W / rect.width),
    y: (e.clientY - rect.top) * (CANVAS_H / rect.height),
  };
}

// ── Mouse/Touch handlers ─────────────────────────────────────────────── //

function onMouseDown(e) {
  e.preventDefault();
  painting = true;
  const { x, y } = canvasCoords(e);
  lastX = x;
  lastY = y;
  pushUndo();
  redoStack = [];
  drawStroke(x, y, x, y);
}

function onMouseMove(e) {
  if (!painting) return;
  const { x, y } = canvasCoords(e);
  drawStroke(lastX, lastY, x, y);
  lastX = x;
  lastY = y;
}

function onMouseUp() {
  painting = false;
}

function onTouchStart(e) {
  e.preventDefault();
  if (e.touches.length !== 1) return;
  const touch = e.touches[0];
  const rect = canvas.getBoundingClientRect();
  const x = (touch.clientX - rect.left) * (CANVAS_W / rect.width);
  const y = (touch.clientY - rect.top) * (CANVAS_H / rect.height);
  painting = true;
  lastX = x;
  lastY = y;
  pushUndo();
  redoStack = [];
  drawStroke(x, y, x, y);
}

function onTouchMove(e) {
  e.preventDefault();
  if (!painting || e.touches.length !== 1) return;
  const touch = e.touches[0];
  const rect = canvas.getBoundingClientRect();
  const x = (touch.clientX - rect.left) * (CANVAS_W / rect.width);
  const y = (touch.clientY - rect.top) * (CANVAS_H / rect.height);
  drawStroke(lastX, lastY, x, y);
  lastX = x;
  lastY = y;
}

// ── Drawing ──────────────────────────────────────────────────────────── //

function drawStroke(x1, y1, x2, y2) {
  maskCtx.lineWidth = brushSize;
  maskCtx.lineCap = 'round';
  maskCtx.lineJoin = 'round';
  maskCtx.strokeStyle = tool === 'brush' ? '#fff' : '#000';
  maskCtx.beginPath();
  maskCtx.moveTo(x1, y1);
  maskCtx.lineTo(x2, y2);
  maskCtx.stroke();
  render();
}

// Reusable overlay canvas for rendering.
let _overlayCanvas = null;
let _overlayCtx = null;

function render() {
  ctx.clearRect(0, 0, CANVAS_W, CANVAS_H);

  // 1. Draw reference image as background.
  if (bgImage && bgImage.complete) {
    ctx.drawImage(bgImage, 0, 0, CANVAS_W, CANVAS_H);
  }

  // 2. Build red overlay from mask.
  if (!_overlayCanvas) {
    _overlayCanvas = document.createElement('canvas');
    _overlayCanvas.width = CANVAS_W;
    _overlayCanvas.height = CANVAS_H;
    _overlayCtx = _overlayCanvas.getContext('2d');
  }

  const maskData = maskCtx.getImageData(0, 0, CANVAS_W, CANVAS_H);
  const overlay = _overlayCtx.createImageData(CANVAS_W, CANVAS_H);

  for (let i = 0; i < maskData.data.length; i += 4) {
    if (maskData.data[i] > 128) {
      overlay.data[i] = 255;     // R
      overlay.data[i + 1] = 0;   // G
      overlay.data[i + 2] = 0;   // B
      overlay.data[i + 3] = 100; // A
    }
    // else: stays 0,0,0,0 (transparent)
  }
  _overlayCtx.putImageData(overlay, 0, 0);

  // 3. Composite overlay on top of reference.
  ctx.drawImage(_overlayCanvas, 0, 0);
}

// ── Undo / Redo ──────────────────────────────────────────────────────── //

function pushUndo() {
  const data = maskCtx.getImageData(0, 0, CANVAS_W, CANVAS_H);
  undoStack.push(data);
  if (undoStack.length > MAX_UNDO) undoStack.shift();
}

function maskUndo() {
  if (undoStack.length < 2) return; // keep at least initial state
  const current = undoStack.pop();
  redoStack.push(current);
  const prev = undoStack[undoStack.length - 1];
  maskCtx.putImageData(prev, 0, 0);
  render();
}

function maskRedo() {
  if (!redoStack.length) return;
  const next = redoStack.pop();
  undoStack.push(next);
  maskCtx.putImageData(next, 0, 0);
  render();
}

function maskClear() {
  pushUndo();
  redoStack = [];
  maskCtx.fillStyle = '#000';
  maskCtx.fillRect(0, 0, CANVAS_W, CANVAS_H);
  render();
}

// ── Tool / Zoom controls ─────────────────────────────────────────────── //

function setTool(t) {
  tool = t;
  document.getElementById('brush-btn').classList.toggle('active', t === 'brush');
  document.getElementById('eraser-btn').classList.toggle('active', t === 'eraser');
}

function updateBrushSize(val) {
  brushSize = parseInt(val);
  document.getElementById('brush-size-label').textContent = val;
}

function setZoom(z) {
  zoom = z;
  const container = document.getElementById('canvas-container');
  container.style.transform = `scale(${z})`;
  container.style.transformOrigin = 'top left';
  document.querySelectorAll('.zoom-btn').forEach(btn => {
    btn.classList.toggle('active', parseInt(btn.dataset.zoom) === z);
  });
}

// ── Load existing mask ───────────────────────────────────────────────── //

function loadMaskFromUrl(maskUrl) {
  const img = new Image();
  img.crossOrigin = 'anonymous';
  img.onload = () => {
    maskCtx.drawImage(img, 0, 0, CANVAS_W, CANVAS_H);
    pushUndo();
    render();
  };
  img.src = maskUrl;
}

// ── Read-only mode (for finished tasks) ──────────────────────────────── //

function setMaskReadOnly(readOnly) {
  if (!canvas) return;
  if (readOnly) {
    canvas.removeEventListener('mousedown', onMouseDown);
    canvas.removeEventListener('mousemove', onMouseMove);
    canvas.removeEventListener('mouseup', onMouseUp);
    canvas.removeEventListener('mouseleave', onMouseUp);
    canvas.style.cursor = 'default';
  }
}

// ── Export ────────────────────────────────────────────────────────────── //

function exportMask() {
  return new Promise((resolve) => {
    maskCanvas.toBlob(resolve, 'image/png');
  });
}
