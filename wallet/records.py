from . import views

from .models import PasswordHistory, Password, SharedPassword, ActionLogs

from django.http import *
from django.shortcuts import render, render, redirect
from django.views import View

import datetime

class RecordsView(View):
    def get(self, request):
        id_pass = request.GET['id_password']
        data = PasswordHistory.objects.filter(id_password_id = id_pass)
        return render(request, 'records.html', {'data': data})

    def post(self, request):
        version = request.POST['restore']

        data = PasswordHistory.objects.get(id = version)
        actual_data = Password.objects.filter(id = data.id_password_id)

        for item in actual_data:

            PasswordHistory.objects.create(id_password_id = item.id, login = item.login, password = item.password, description = item.description, web_address = item.web_address, lastTime = datetime.datetime.now())
            
            item.login = data.login
            item.password = data.password
            item.web_address = data.web_address
            item.description = data.description
            item.save()
            id_pass = item.id

        master = request.session.get('password')
        try:
            views.master_decode(master, actual_data)
        except:
            return HttpResponse("Wrong master password!")

        for item in actual_data:
            clear_password = item.password
        
        shared_data = SharedPassword.objects.filter(id_password_id = id_pass)
        for item in shared_data:
            item.guest_password = clear_password
            item.save()
        
        ActionLogs.objects.create(id_user_id = request.session.get('user'), function = "RESTORE", accessTime = datetime.datetime.now())
        return HttpResponseRedirect('/main/')
