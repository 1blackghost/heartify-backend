from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User 
from django.views.decorators.csrf import csrf_exempt
from .models import HeartDiseasePrediction,PredictionResult
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import load_model
import numpy as np
import threading
import json

def predict_heart_disease_thread(user_id):
    print("started!!")
    heart_conditions = HeartDiseasePrediction.objects.filter(user_id=user_id).first()

    if heart_conditions:
        new_person_data = {
            'male': [heart_conditions.male],
            'age': [heart_conditions.age],
            'education': [heart_conditions.education],
            'currentSmoker': [heart_conditions.currentSmoker],
            'cigsPerDay': [heart_conditions.cigsPerDay],
            'BPMeds': [heart_conditions.BPMeds],
            'prevalentStroke': [heart_conditions.prevalentStroke],
            'prevalentHyp': [heart_conditions.prevalentHyp],
            'diabetes': [heart_conditions.diabetes],
            'totChol': [heart_conditions.totChol],
            'sysBP': [heart_conditions.sysBP],
            'diaBP': [heart_conditions.diaBP],
            'BMI': [heart_conditions.BMI],
            'heartRate': [heart_conditions.heartRate],
            'glucose': [heart_conditions.glucose]
        }

        ensemble_model = load_model('heartifyt.h5')
        new_person_df = pd.DataFrame(new_person_data)
        scaler = MinMaxScaler()
        new_person_scaled = scaler.fit_transform(new_person_df)
        new_person_cnn_gru = np.reshape(new_person_scaled, (new_person_scaled.shape[0], 1, new_person_scaled.shape[1]))
        new_person_dnn = new_person_scaled
        predicted_probs = ensemble_model.predict([new_person_cnn_gru, new_person_dnn])
        prediction = (predicted_probs > 0.5).astype(int)
        
        result = {
            'prediction': int(prediction[0][0]),  
            'prediction_probability': float(predicted_probs[0][0])  
        }
        print("SAVING!!")

        prediction_entry = PredictionResult.objects.get(user_id=user_id)
        prediction_entry.started = False
        prediction_entry.result = result
        prediction_entry.save()
        print("STOPPING!!")
    else:
        prediction_entry = PredictionResult.objects.get(user_id=user_id)
        prediction_entry.started = False
        prediction_entry.result = {'error': 'No heart condition data found for this user'}
        prediction_entry.save()
        print("STOPPING!!")


@login_required
def predict_heart_disease_view(request):
    prediction_entry, created = PredictionResult.objects.get_or_create(user=request.user)
    prediction_entry.started = True
    prediction_entry.result = None  
    prediction_entry.save()
    thread = threading.Thread(target=predict_heart_disease_thread, args=(request.user.id,))
    thread.start()


    return JsonResponse({'started': True}, status=200)


@login_required
def get_results_view(request):
    prediction_entry = PredictionResult.objects.get(user=request.user)

    if prediction_entry.started:
        return JsonResponse({'message': 'Prediction in progress'}, status=202)

    if prediction_entry.result:
        return JsonResponse({'prediction': prediction_entry.result}, status=200)
    else:
        return JsonResponse({'message': 'No prediction result available'}, status=404)


@csrf_exempt
def signup_view(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')

        if User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'Username already exists'}, status=400)

        user = User.objects.create_user(username=username, email=email, password=password)

        auth_login(request, user)
        return JsonResponse({'message': 'User registered successfully'}, status=201)
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')

        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            auth_login(request, user)
            return JsonResponse({'message': 'Login successful'}, status=200)
        else:
            return JsonResponse({'error': 'Invalid credentials'}, status=400)
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
@login_required
def save_heart_condition(request):
    if request.method == 'POST':
        data = json.loads(request.body)

        heart_condition_data = {
            'male': int(data.get('male')),
            'age': int(data.get('age')),
            'education': int(data.get('education')),
            'currentSmoker': int(data.get('currentSmoker')),
            'cigsPerDay': int(data.get('cigsPerDay')),
            'BPMeds': int(data.get('BPMeds')),
            'prevalentStroke': int(data.get('prevalentStroke')),
            'prevalentHyp': int(data.get('prevalentHyp')),
            'diabetes': int(data.get('diabetes')),
            'totChol': int(data.get('totChol')),
            'sysBP': int(data.get('sysBP')),
            'diaBP': int(data.get('diaBP')),
            'BMI': int(data.get('BMI')),
            'heartRate': int(data.get('heartRate')),
            'glucose': int(data.get('glucose')),
        }

        user = request.user
        HeartDiseasePrediction.objects.create(
            user=user,
            male=heart_condition_data['male'],
            age=heart_condition_data['age'],
            education=heart_condition_data['education'],
            currentSmoker=heart_condition_data['currentSmoker'],
            cigsPerDay=heart_condition_data['cigsPerDay'],
            BPMeds=heart_condition_data['BPMeds'],
            prevalentStroke=heart_condition_data['prevalentStroke'],
            prevalentHyp=heart_condition_data['prevalentHyp'],
            diabetes=heart_condition_data['diabetes'],
            totChol=heart_condition_data['totChol'],
            sysBP=heart_condition_data['sysBP'],
            diaBP=heart_condition_data['diaBP'],
            BMI=heart_condition_data['BMI'],
            heartRate=heart_condition_data['heartRate'],
            glucose=heart_condition_data['glucose'],
        )

        return JsonResponse({'message': 'Heart condition data saved successfully'}, status=201)

    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
@login_required
def get_heart_condition(request):
    user = request.user
    heart_conditions = HeartDiseasePrediction.objects.filter(user=user)

    if not heart_conditions:
        return JsonResponse({'message': 'No heart condition data available for this user'}, status=404)

    predictions_data = [
        {
            'male': prediction.male,
            'age': prediction.age,
            'education': prediction.education,
            'currentSmoker': prediction.currentSmoker,
            'cigsPerDay': prediction.cigsPerDay,
            'BPMeds': prediction.BPMeds,
            'prevalentStroke': prediction.prevalentStroke,
            'prevalentHyp': prediction.prevalentHyp,
            'diabetes': prediction.diabetes,
            'totChol': prediction.totChol,
            'sysBP': prediction.sysBP,
            'diaBP': prediction.diaBP,
            'BMI': prediction.BMI,
            'heartRate': prediction.heartRate,
            'glucose': prediction.glucose,
            'date': prediction.date
        }
        for prediction in heart_conditions
    ]

    return JsonResponse({'heart_conditions': predictions_data}, status=200)
