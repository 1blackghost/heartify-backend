import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import load_model

def predict_heart_disease(new_person_data):
    ensemble_model = load_model('heartifyt.h5')
    new_person_df = pd.DataFrame(new_person_data)
    scaler = MinMaxScaler()
    new_person_scaled = scaler.fit_transform(new_person_df)
    new_person_cnn_gru = np.reshape(new_person_scaled, (new_person_scaled.shape[0], 1, new_person_scaled.shape[1]))
    new_person_dnn = new_person_scaled
    predicted_probs = ensemble_model.predict([new_person_cnn_gru, new_person_dnn])
    prediction = (predicted_probs > 0.5).astype(int)
    result = f"Predicted Probability of Heart Disease: {predicted_probs[0][0]:.2f}\n"
    result += f"Prediction: {'Heart Disease' if prediction[0][0] == 1 else 'No Heart Disease'}"
    return result

'''
new_person_data = {
    'male': [1],
    'age': [39],
    'education': [4],
    'currentSmoker': [0],
    'cigsPerDay': [0],
    'BPMeds': [0],
    'prevalentStroke': [0],
    'prevalentHyp': [0],
    'diabetes': [0],
    'totChol': [195],
    'sysBP': [106],
    'diaBP': [70],
    'BMI': [26.97],
    'heartRate': [80],
    'glucose': [77]
}

prediction_result = predict_heart_disease(new_person_data)
print(prediction_result)
'''