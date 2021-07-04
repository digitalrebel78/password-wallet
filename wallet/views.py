from . import logview
from .logview import LogView
from .sharedview import SharedView

from django.http import *
from django.shortcuts import render, render, redirect
from django.template import RequestContext
from django.contrib.auth.decorators import login_required
from django.forms import Form, HiddenInput, CharField, ChoiceField, ModelForm
from django.views import View

from django.db import models
from .models import User
from .models import Password
from .models import SharedPassword
from .models import Logs
from .models import ActionLogs

from django.utils import timezone

import random
import datetime
from datetime import timedelta

import secrets
import hashlib
import hmac
import binascii
import codecs

from base64 import b64encode, b64decode

import base64

PEPPER = "pepper"
BLOCK_SIZE = 128


def index(request):
    return HttpResponse("Hello, world. You're at the index.")


def login(request):

    logs = LogView()
    if request.session.get('user') != None:
        return HttpResponseRedirect('/main/')
    
    username = password = ''
    if request.POST:
        username = request.POST['username']
        password = request.POST['password']

        if username == "" or password == "":
            return HttpResponse("Please fill the form!")
        try:
            if User.objects.get(login=username) is not None:
                old_hash = User.objects.get(login=username).password_hash
                enc_type = User.objects.get(login=username).isPasswordKeptAsHash
                if enc_type == 1:
                    salt = User.objects.get(login=username).salt  
                    new_hash = hashlib.sha512((PEPPER + salt + password).encode("utf-8")).hexdigest()
                else:
                    key = bytes.fromhex(User.objects.get(login=username).salt)
                    new_hash = hmac_sha512(key, password)
                if new_hash == old_hash:
                    filterargs = { 'id_user_id': User.objects.get(login=username).id, 'ip': logs.get_ip_address(request) }
                    logs_data = Logs.objects.filter(**filterargs).order_by('-date').first()
                    #return HttpResponse(logs_data)
                    if logs_data:
                        if logs_data.blockadeTime:
                            if logs_data.blockadeTime.replace(tzinfo=None) >= datetime.datetime.now():
                                blocked_prompt = "This account is blocked until " + str(logs_data.blockadeTime)
                                return HttpResponse(blocked_prompt);
                    request.session['user'] = User.objects.get(login=username).id
                    request.session['enable'] = False
                    Logs.objects.create(id_user_id = request.session['user'], date = datetime.datetime.now(), isSuccessful = True, ip = logs.get_ip_address(request), blockadeTime = None)
                    return HttpResponseRedirect('/main/')
                else:
                    Logs.objects.create(id_user_id = User.objects.get(login=username).id, date = datetime.datetime.now(), isSuccessful = False, ip = logs.get_ip_address(request), blockadeTime = None)
                    request.session['user'] = User.objects.get(login=username).id
                    times = logs.get_failed_attempts(request)
                    filterargs = { 'id_user_id': request.session.get('user'), 'ip': logs.get_ip_address(request) }
                    request.session['user'] = None
                    logs_data_all = Logs.objects.filter(**filterargs).order_by('-date')
                    logs_data = logs_data_all.first()
                    #return HttpResponse(times)
                    if times == 2:
                        logs_data.blockadeTime = datetime.datetime.now() + timedelta(seconds = 5)
                        logs_data.save()
                    if times == 3:
                        logs_data.blockadeTime = datetime.datetime.now() + timedelta(seconds = 10)
                        logs_data.save()
                    if times >= 4:
                        if logs.was_logged_from_ip(request, logs_data_all):
                            logs_data.blockadeTime = datetime.datetime.now() + timedelta(minutes = 2)
                        else:
                            logs_data.blockadeTime = datetime.datetime.max
                        logs_data.save()
                    return HttpResponse("Login failed")
        except User.DoesNotExist:
            return HttpResponse("Login failed")

        return HttpResponse("Login failed")
    return render(request, 'login.html', None)


def logout(request):
    request.session['user'] = None
    request.session['password'] = None
    request.session['enable'] = False
    return render(request, 'logout.html', None)


def register(request):

    if request.session.get('user') != None:
        return HttpResponseRedirect('/main/')
    
    username = password = ''
    if request.POST:
        username = request.POST['username']
        password = request.POST['password']
        password_copy = request.POST['password_copy']
        enc_type = request.POST['type']

        if username == "" or password == "" or password_copy == "":
            return HttpResponse("Please fill the form!")
        elif password == password_copy:
            if enc_type == "sha":
                salt = secrets.token_hex(8)
                password_hash = hashlib.sha512((PEPPER + salt + password).encode("utf-8")).hexdigest()
                User.objects.create(login = username, password_hash = password_hash, salt = salt, isPasswordKeptAsHash = 1)
                request.session['user'] = User.objects.get(login=username).id
                return HttpResponseRedirect('/main/')
            elif enc_type == "hmac":
                key = ''
                for _ in range(10):
                    random_integer = random.randint(0, 255)
                    key += (chr(random_integer))
                key = hashlib.md5(key.encode(encoding='UTF-8', errors='ignore')).digest()
                password_hash = hmac_sha512(key, password)
                try:
                    User.objects.create(login = username, password_hash = password_hash, salt = key.hex(), isPasswordKeptAsHash = 0)
                except IntegrityError:
                    return HttpResponse("This login is not available!")
                request.session['user'] = User.objects.get(login=username).id
                return HttpResponseRedirect('/main/')
        else:
            return HttpResponse("Passwords do not match!")
    return render(request, 'register.html', None)


def hmac_sha512(key, message):
    message = message.encode(encoding='UTF-8', errors='ignore')
    return hmac.new(key, message, hashlib.sha512).hexdigest().upper()


def xorbytes(abytes, bbytes):
    return bytes([a ^ b for a, b in zip(abytes[::-1], bbytes[::-1])][::-1])


def change_password(request):

    if request.session.get('user') == None:
        return HttpResponseRedirect('/login/')

    if request.POST:
        username = request.session.get('user')
        old_password = request.POST['old_password']
        password = request.POST['password']
        password_copy = request.POST['password_copy']
        old_enc_type = request.POST['type']
        enc_type = request.POST['type']

        if old_password == "" or password == "" or password_copy == "":
            return HttpResponse("Please fill the form!")
        elif password == password_copy:

            old_hash = User.objects.get(id=username).password_hash
            old_enc_type = User.objects.get(id=username).isPasswordKeptAsHash
            if old_enc_type == 1:
                salt = User.objects.get(id=username).salt  
                new_hash = hashlib.sha512((PEPPER + salt + old_password).encode("utf-8")).hexdigest()
            else:
                key = bytes.fromhex(User.objects.get(id=username).salt)
                new_hash = hmac_sha512(key, old_password)
            if new_hash == old_hash:

                credentials = User.objects.filter(id = username)
                
                if enc_type == "sha":
                    salt = secrets.token_hex(8)
                    password_hash = hashlib.sha512((PEPPER + salt + password).encode("utf-8")).hexdigest()
                    for user in credentials:
                        user.password_hash = password_hash
                        user.salt = salt
                        user.isPasswordKeptAsHash = 1
                        user.save()
                    return HttpResponseRedirect('/main/')
                
                elif enc_type == "hmac":
                    key = ''
                    for _ in range(10):
                        random_integer = random.randint(0, 255)
                        key += (chr(random_integer))
                    key = hashlib.md5(key.encode(encoding='UTF-8', errors='ignore')).digest()
                    password_hash = hmac_sha512(key, password)

                    for user in credentials:
                        user.password_hash = password_hash
                        user.salt = key.hex()
                        user.isPasswordKeptAsHash = 0
                        user.save()
                    return HttpResponseRedirect('/main/')
                
            else:
                return HttpResponse("Password change actually failed")
        else:
            return HttpResponse("Passwords do not match!")
    
    return render(request, 'change_password.html', None)


def main(request):

    if request.session.get('user') == None:
        return HttpResponseRedirect('/login/')

    data = Password.objects.filter(id_user_id = request.session.get('user'))
    ActionLogs.objects.create(id_user_id = request.session.get('user'), function = "READ", accessTime = datetime.datetime.now())
    
    if request.POST:
        if request.POST.get('enable'):
            if request.POST['enable'] == "True":
                request.session['enable'] = True
                return HttpResponseRedirect('/main/')
            elif request.POST['enable'] == "False":
                request.session['enable'] = False
                return HttpResponseRedirect('/main/')

        if request.POST.get('delete'):
            if request.POST['delete']:
                id_pass = request.POST['delete']
                SharedPassword.objects.filter(id_password_id = id_pass).all().delete()
                Password.objects.filter(id = id_pass).all().delete()
                ActionLogs.objects.create(id_user_id = request.session.get('user'), function = "DELETE", accessTime = datetime.datetime.now())
                return HttpResponseRedirect('/main/')
        
        login = request.POST['login']
        password = request.POST['password']
        address = request.POST['address']
        description = request.POST['description']
        master = request.session.get('password')
        
        if password == "":
            return HttpResponse("Please enter new password to add!")
        elif master == None:
            return HttpResponse("Please enter the master password!")

        master_key = hashlib.md5(master.encode(encoding='UTF-8')).digest()
        password = bytes(password.encode(encoding='ascii',errors='strict'))
        password = (xorbytes(password, master_key))
        
        Password.objects.create(login = login, password = password.hex(), description = description, web_address = address, id_user_id = request.session.get('user'))
        ActionLogs.objects.create(id_user_id = request.session.get('user'), function = "CREATE", accessTime = datetime.datetime.now())
        #data = Password.objects.filter(id_user_id = request.session.get('user'))
        return HttpResponseRedirect('/main/')

    if request.GET:
        master = request.GET['master_password']
        if master == "":
            return HttpResponse("Please enter the master password!")
        request.session['password'] = master
        try:
            master_decode(request.session.get('password'), data)
        except:
            return HttpResponse("Wrong master password!")

        return HttpResponseRedirect('/main/')
    
    if request.session.get('password'):
        try:
            master_decode(request.session.get('password'), data)
        except:
            return HttpResponse("Wrong master password!")
        if request.session.get('enable'):
            return render(request, 'main_pass_enabled.html', {'data':data})
        else:
            return render(request, 'main_pass.html', {'data':data})
    else:
        return render(request, 'main.html', {'data':data})


def master_decode(master, data):
    master_key = hashlib.md5(master.encode(encoding='UTF-8')).digest()
    
    for item in data:
        byte_hash = xorbytes(bytes.fromhex(item.password), master_key).decode(encoding='utf-8')
        item.password = byte_hash


def change_master(request):

    if request.session.get('user') == None:
        return HttpResponseRedirect('/login/')

    if request.POST:
        old_password = request.POST['old_password']
        password = request.POST['password']
        password_copy = request.POST['password_copy']

        if old_password == "" or password == "" or password_copy == "":
            return HttpResponse("Please fill the form!")
        elif old_password != request.session.get('password'):
            return HttpResponse("Wrong master password!")
        elif password == password_copy:
            data = Password.objects.filter(id_user_id = request.session.get('user'))
            old_master_key = hashlib.md5(old_password.encode(encoding='UTF-8')).digest()
            new_master_key = hashlib.md5(password.encode(encoding='UTF-8')).digest()
            for item in data:
                word = xorbytes(bytes.fromhex(item.password), old_master_key)
                new_word = (xorbytes(word, new_master_key)).hex()
                item.password = new_word
                item.save()
            request.session['password'] = password
            return HttpResponseRedirect('/main/')
        else:
            return HttpResponse("Passwords do not match!")
    
    return render(request, 'change_master.html', None)
