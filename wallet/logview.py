from .models import Logs

from django.shortcuts import render, render, redirect
from django.views import View

class LogView(View):

    def get(self, request):

        data = Logs.objects.filter(id_user_id = request.session.get('user'))
        return render(request, 'logs.html', {'data':data, 'count':self.get_attempts(request)})
    
    def get_ip_address(self, request):

        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def get_attempts(self, request):

        data = Logs.objects.filter(id_user_id = request.session.get('user')).order_by('-date')
        count = 0
        for item in data:
            if item.isSuccessful:
                count += 1
            else:
                return count
        return count

    def get_failed_attempts(self, request):

        data = Logs.objects.filter(id_user_id = request.session.get('user')).order_by('-date')
        count = 0
        for item in data:
            if item.isSuccessful:
                return count
            else:
                count += 1
        return count

    def was_logged_from_ip(self, request, query):

        for item in query:
            if item.isSuccessful:
                return True
        return False
