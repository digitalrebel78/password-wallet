from . import views

from .models import Password, SharedPassword, ActionLogs, PasswordHistory

from django.http import *
from django.shortcuts import render, render, redirect
from django.views import View

import hashlib
import datetime

class EditView(View):

    def get(self, request):
        id_pass = request.GET['id_password']

        data = Password.objects.filter(id = id_pass)
        
        master = request.session.get('password')
        try:
            views.master_decode(master, data)
        except:
            return HttpResponse("Wrong master password!")

        return render(request, 'edit.html', {'data':data, 'id_pass':id_pass})
        
    def post(self, request):
        id_pass = request.POST['id_password']

        login = request.POST['login']
        clear_password = password = request.POST['password']
        address = request.POST['address']
        description = request.POST['description']
        master = request.session.get('password')

        if password == "":
            return HttpResponse("Please enter password to edit entry!")
        
        master_key = hashlib.md5(master.encode(encoding='UTF-8')).digest()
        password = bytes(password.encode(encoding='ascii',errors='strict'))
        password = (views.xorbytes(password, master_key))
    
        data = Password.objects.get(id = id_pass)

        PasswordHistory.objects.create(id_password_id = data.id, login = data.login, password = data.password, description = data.description, web_address = data.web_address, lastTime = datetime.datetime.now())

        
        data.login = login
        data.password = password.hex()
        data.web_address = address
        data.description = description
        data.save()
        new_id = data.id
        
        shared_data = SharedPassword.objects.filter(id_password_id = id_pass)
        for item in shared_data:
            item.guest_password = clear_password
            item.id_password_id = new_id
            item.save()

        ActionLogs.objects.create(id_user_id = request.session.get('user'), function = "UPDATE", accessTime = datetime.datetime.now())
        return HttpResponseRedirect('/main/')
