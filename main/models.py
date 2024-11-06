from django.db import models
from django.contrib.auth.models import User



class PredictionResult(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    started = models.BooleanField(default=False)
    result = models.JSONField(null=True, blank=True) 
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Prediction for {self.user.username}"
    
class HeartDiseasePrediction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE) 
    male = models.IntegerField()  
    age = models.IntegerField()
    education = models.IntegerField()
    currentSmoker = models.IntegerField() 
    cigsPerDay = models.IntegerField()
    BPMeds = models.IntegerField()  
    prevalentStroke = models.IntegerField()  
    prevalentHyp = models.IntegerField() 
    diabetes = models.IntegerField() 
    totChol = models.IntegerField()
    sysBP = models.IntegerField()
    diaBP = models.IntegerField()
    BMI = models.IntegerField() 
    heartRate = models.IntegerField()
    glucose = models.IntegerField()
    date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Prediction for {self.user.username} at age {self.age} | Probability: {self.prediction_probability}"