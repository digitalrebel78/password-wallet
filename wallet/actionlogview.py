from .models import ActionLogs

from django.shortcuts import render, render, redirect
from django.views import View

class ActionLogView(View):

    def get(self, request):

        data = ActionLogs.objects.filter(id_user_id = request.session.get('user'))
        return render(request, 'actionlogs.html', {'data':data})

    def post(self, request):

        query = request.POST['select']
        if query == "all":
            data = ActionLogs.objects.filter(id_user_id = request.session.get('user'))
        else:
            data = ActionLogs.objects.filter(id_user_id = request.session.get('user'), function = query)
        return render(request, 'actionlogs.html', {'data':data})
