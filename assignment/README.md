# Facial Emotion Recognition

A Python application that detects faces and classifies emotions in real time (webcam) or from a labeled image dataset (batch mode). It uses **OpenCV** for face detection and **DeepFace** for emotion classification.

## Features

- **Face Detection** — Haar Cascade classifier with CLAHE-enhanced preprocessing.
- **Emotion Classification** — Recognizes 7 emotions (angry, disgust, fear, happy, sad, surprise, neutral) via DeepFace.
- **Live Overlay** — Bounding boxes, dominant emotion label, and per-face mini bar chart drawn on each frame.
- **Batch Evaluation** — Calculates accuracy and generates a confusion matrix heatmap from labeled folders.

## Requirements

Install dependencies:

```bash
pip install opencv-python deepface pandas matplotlib seaborn scikit-learn
```

A working webcam is required for webcam mode.

## Usage

### Webcam Mode

Runs real-time emotion detection using your webcam.

```bash
python main.py --mode webcam
```

**Controls:**
| Key | Action |
|-----|--------|
| `s` | Save a screenshot |
| `q` | Quit |

### Batch Mode

Processes a directory of labeled images and outputs accuracy metrics.

```bash
python main.py --mode batch --data dataset
```

- `--data` — path to the dataset directory (default: `dataset`).

**Expected folder structure:**

```
dataset/
├── happy/
│   ├── img1.jpg
│   └── img2.jpg
├── sad/
│   └── img3.jpg
└── ...
```

Each subfolder name is treated as the ground-truth emotion label.

**Outputs:**
| File | Description |
|------|-------------|
| `results.csv` | Per-image emotion scores with true/predicted labels |
| `confusion_matrix.png` | Heatmap of true vs. predicted emotions |
