from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User 
from django.views.decorators.csrf import csrf_exempt
from .models import HeartDiseasePrediction
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import load_model
import numpy as np


@csrf_exempt
def signup_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')
        phone_number = request.POST.get('phone_number')

        if User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'Username already exists'}, status=400)

        user = User.objects.create_user(username=username, email=email, password=password,phone_number=phone_number)

        auth_login(request, user)
        return JsonResponse({'message': 'User registered successfully'}, status=201)
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

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
        heart_condition_data = {
            'male': int(request.POST.get('male')),
            'age': int(request.POST.get('age')),
            'education': int(request.POST.get('education')),
            'currentSmoker': int(request.POST.get('currentSmoker')),
            'cigsPerDay': int(request.POST.get('cigsPerDay')),
            'BPMeds': int(request.POST.get('BPMeds')),
            'prevalentStroke': int(request.POST.get('prevalentStroke')),
            'prevalentHyp': int(request.POST.get('prevalentHyp')),
            'diabetes': int(request.POST.get('diabetes')),
            'totChol': int(request.POST.get('totChol')),
            'sysBP': int(request.POST.get('sysBP')),
            'diaBP': int(request.POST.get('diaBP')),
            'BMI': int(request.POST.get('BMI')),
            'heartRate': int(request.POST.get('heartRate')),
            'glucose': int(request.POST.get('glucose')),
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
