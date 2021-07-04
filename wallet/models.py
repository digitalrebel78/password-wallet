from django.db import models

class User(models.Model):
    login = models.CharField(unique=True, max_length=30)
    password_hash = models.CharField(max_length=512)
    salt = models.CharField(null=True, max_length=20)
    isPasswordKeptAsHash = models.BooleanField(null=True)

class Password(models.Model):
    password = models.CharField(null=True, max_length=256)
    id_user = models.ForeignKey('User', on_delete=models.CASCADE)
    web_address = models.CharField(null=True, max_length=256)
    description = models.CharField(null=True, max_length=256)
    login = models.CharField(null=True, max_length=256)

class PasswordHistory(models.Model):
    id_password = models.ForeignKey('Password', on_delete=models.CASCADE)
    password = models.CharField(null=True, max_length=256)
    web_address = models.CharField(null=True, max_length=256)
    description = models.CharField(null=True, max_length=256)
    login = models.CharField(null=True, max_length=256)
    lastTime = models.DateTimeField(null=False)

class SharedPassword(models.Model):
    id_password = models.ForeignKey('Password', on_delete=models.CASCADE)
    id_user = models.ForeignKey('User', on_delete=models.CASCADE, related_name='host')
    id_guest = models.ForeignKey('User', on_delete=models.CASCADE, related_name='guest')
    guest_password = models.CharField(null=True, max_length=256)

class Logs(models.Model):
    id_user = models.ForeignKey('User', on_delete=models.CASCADE)
    date = models.DateTimeField()
    isSuccessful = models.BooleanField(null=False)
    ip = models.GenericIPAddressField(null=True, max_length=256)
    blockadeTime = models.DateTimeField(null=True)

class ActionLogs(models.Model):
    id_user = models.ForeignKey('User', on_delete=models.CASCADE)
    function = models.CharField(null=False, max_length=256)
    accessTime = models.DateTimeField(null=False)
