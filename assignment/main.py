import cv2
import time
import argparse
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix
from deepface import DeepFace

# ==========================================
# PARTNER A: VISION & WEBCAM (40 Points)
# ==========================================

def preprocess_image(image):
    """Resizes, converts to grayscale, and applies CLAHE."""
    height, width = image.shape[:2]
    new_width = 640
    new_height = int((new_width / width) * height)
    resized = cv2.resize(image, (new_width, new_height))
    
    gray = cv2.cvtColor(resized, cv2.COLOR_BGR2GRAY)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    enhanced_gray = clahe.apply(gray)
    
    return resized, enhanced_gray

def detect_faces(gray_image, scale_factor=1.1, min_neighbors=5):
    """Detects faces using Haar Cascades."""
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    faces = face_cascade.detectMultiScale(gray_image, scaleFactor=scale_factor, minNeighbors=min_neighbors, minSize=(30, 30))
    return faces

# ==========================================
# PARTNER B: CLASSIFICATION & VIZ (40 Points)
# ==========================================

def get_emotions(face_roi):
    """Passes the cropped face to DeepFace and returns all 7 scores safely."""
    try:
        # enforce_detection=False because we already cropped the face using OpenCV
        result = DeepFace.analyze(face_roi, actions=['emotion'], enforce_detection=False, silent=True)
        # DeepFace analyze can return a list of dicts if multiple faces are found, we take the first
        if isinstance(result, list):
            result = result[0]
        return result['emotion'] # Returns dict of 7 emotions and their confidence scores
    except Exception as e:
        print(f"DeepFace error: {e}")
        return None

def draw_visuals(frame, x, y, w, h, emotions):
    """Draws color-coded box, dominant label, and mini bar chart per face."""
    dominant_emotion = max(emotions, key=emotions.get)
    max_score = emotions[dominant_emotion]
    
    cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)
    
    label = f"{dominant_emotion}: {max_score:.1f}%"
    cv2.putText(frame, label, (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
    
    chart_x = x + w + 10
    chart_y = y
    colors = [(255,0,0), (0,255,0), (0,0,255), (255,255,0), (0,255,255), (255,0,255), (255,255,255)]
    
    for i, (emotion, score) in enumerate(emotions.items()):
        bar_w = int((score / 100) * 50) # Max width of 50px
        cv2.putText(frame, emotion[:3], (chart_x, chart_y + (i*15) + 10), cv2.FONT_HERSHEY_SIMPLEX, 0.3, (255,255,255), 1)
        cv2.rectangle(frame, (chart_x + 25, chart_y + (i*15) + 2), (chart_x + 25 + bar_w, chart_y + (i*15) + 10), colors[i%len(colors)], -1)

# ==========================================
# SHARED: EXECUTION MODES (20 Points)
# ==========================================

def run_webcam():
    """Real-time webcam loop with FPS, frame skipping, and key controls."""
    cap = cv2.VideoCapture(0)
    frame_counter = 0
    skip_frames = 5 
    
    tracked_faces = [] 
    
    prev_time = time.time()
    
    while True:
        ret, frame = cap.read()
        if not ret:
            break
            
        curr_time = time.time()
        fps = 1 / (curr_time - prev_time)
        prev_time = curr_time
        cv2.putText(frame, f"FPS: {int(fps)}", (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
        
        display_frame, gray_frame = preprocess_image(frame)
        frame_counter += 1
        
        if frame_counter % skip_frames == 0:
            tracked_faces = []
            faces = detect_faces(gray_frame)
            
            for (x, y, w, h) in faces:
                face_roi = display_frame[y:y+h, x:x+w]
                emotions = get_emotions(face_roi)
                if emotions:
                    tracked_faces.append((x, y, w, h, emotions))
        
        for (x, y, w, h, emotions) in tracked_faces:
            draw_visuals(display_frame, x, y, w, h, emotions)
            
        cv2.imshow("Webcam Mode - Press 's' to save, 'q' to quit", display_frame)
        
        key = cv2.waitKey(1) & 0xFF
        if key == ord('q'):
            break
        elif key == ord('s'):
            cv2.imwrite(f"screenshot_{int(time.time())}.png", display_frame)
            print("Screenshot saved.")
            
    cap.release()
    cv2.destroyAllWindows()

def run_batch(data_dir):
    """Processes folders of images, calculates accuracy, creates confusion matrix."""
    results = []
    true_labels = []
    pred_labels = []
    
    for true_emotion in os.listdir(data_dir):
        emotion_path = os.path.join(data_dir, true_emotion)
        if not os.path.isdir(emotion_path):
            continue
            
        for img_name in os.listdir(emotion_path):
            img_path = os.path.join(emotion_path, img_name)
            img = cv2.imread(img_path)
            if img is None:
                continue
                
            display_frame, gray_frame = preprocess_image(img)
            faces = detect_faces(gray_frame)
            
            if len(faces) == 0:
                print(f"No face found in {img_name}")
                continue
                
            x, y, w, h = faces[0]
            face_roi = display_frame[y:y+h, x:x+w]
            emotions = get_emotions(face_roi)
            
            if emotions:
                pred_emotion = max(emotions, key=emotions.get)
                true_labels.append(true_emotion.lower())
                pred_labels.append(pred_emotion.lower())
                
                emotions['true_label'] = true_emotion
                emotions['predicted'] = pred_emotion
                emotions['filename'] = img_name
                results.append(emotions)

    df = pd.DataFrame(results)
    df.to_csv('results.csv', index=False)
    print("Saved batch results to results.csv")
    
    correct = sum(1 for t, p in zip(true_labels, pred_labels) if t == p)
    accuracy = correct / len(true_labels) if true_labels else 0
    print(f"Overall Accuracy: {accuracy:.2f}")
    
    labels = list(set(true_labels + pred_labels))
    cm = confusion_matrix(true_labels, pred_labels, labels=labels)
    
    plt.figure(figsize=(10, 7))
    sns.heatmap(cm, annot=True, fmt='d', xticklabels=labels, yticklabels=labels, cmap='Blues')
    plt.title('Emotion Classification Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.savefig('confusion_matrix.png')
    print("Saved confusion matrix to confusion_matrix.png")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Facial Emotion Recognition Project")
    parser.add_argument('--mode', type=str, choices=['webcam', 'batch'], required=True, help="Run mode: webcam or batch")
    parser.add_argument('--data', type=str, default='dataset', help="Directory containing folders of labeled images for batch mode")
    
    args = parser.parse_args()
    
    if args.mode == 'webcam':
        run_webcam()
    elif args.mode == 'batch':
        if not os.path.exists(args.data):
            print(f"Error: Directory '{args.data}' not found. Please create it and add labeled subfolders for batch mode.")
        else:
            run_batch(args.data)