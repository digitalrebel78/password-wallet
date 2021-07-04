from .models import SharedPassword, Password, User, ActionLogs
from . import views

from django.http import *
from django.shortcuts import render, render, redirect
from django.views import View

import datetime

class SharedView(View):

    def get(self, request):

        user = request.session.get('user')
        
        shared_data = SharedPassword.objects.filter(id_user_id = user)
        out_data = []
        for item in shared_data:
            instance = Password.objects.filter(id = item.id_password_id)
            
            for item_guest in User.objects.filter(id = item.id_guest_id):
                guest = item_guest.login
            for item_pass in instance:
                out_data.append(SharedPasswordTable(item.id_password_id, item_pass.login, item.guest_password, item_pass.web_address, item_pass.description, guest))

        #user = request.session.get('user')
        shared_data = SharedPassword.objects.filter(id_guest_id = user)
        in_data = []
        for item in shared_data:
            instance = Password.objects.filter(id = item.id_password_id)
            
            for item_host in User.objects.filter(id = item.id_user_id):
                host = item_host.login
            for item_pass in instance:
                in_data.append(SharedPasswordTable(None, item_pass.login, item.guest_password, item_pass.web_address, item_pass.description, host))
                
        return render(request, 'shared.html', {'out_data':out_data, 'in_data':in_data})

    def post(self, request):

        id_guest = request.POST['user_login']
        id_guest_del = request.POST['user_delete']
        id_password = request.POST['id_password']
        
        if id_guest == "":
            return HttpResponse("Please enter user login/email to share password!")
        elif id_guest == 'None':
            #for del_item in User.objects.get(login = id_guest_del):
            #    del_id = del_item.id
            del_id = User.objects.get(login = id_guest_del).id
            SharedPassword.objects.filter(id_password_id = id_password, id_guest_id = del_id).all().delete()
            ActionLogs.objects.create(id_user_id = request.session.get('user'), function = "WITHDRAW", accessTime = datetime.datetime.now())
            return HttpResponseRedirect('/shared/')

        try:
            guest = User.objects.get(login = id_guest).id
        except:
            return HttpResponse("No user with this name exists!")
        if SharedPassword.objects.filter(id_password_id = id_password, id_guest_id = guest):
            return HttpResponse("You have already shared this password with that user!")
        
        password_data = Password.objects.filter(id = id_password)
        try:
            views.master_decode(request.session.get('password'), password_data)
        except:
            return HttpResponse("Wrong master password!")

        password = password_data[0].password
        
        SharedPassword.objects.create(id_password_id = id_password, id_user_id = request.session.get('user'), id_guest_id = guest, guest_password = password)
        ActionLogs.objects.create(id_user_id = request.session.get('user'), function = "SHARE", accessTime = datetime.datetime.now())
        return HttpResponseRedirect('/shared/')

class SharedPasswordTable():
    def __init__(self, id_password, login, password, web_address, description, user_login):
        self.id_password = id_password
        self.login = login
        self.password = password
        self.web_address = web_address
        self.description = description
        self.user_login = user_login
