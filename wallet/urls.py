from django.urls import path

from . import views
from .logview import LogView
from .sharedview import SharedView
from .editview import EditView
from .actionlogview import ActionLogView
from .records import RecordsView

from .models import Logs

urlpatterns = [
    # path("", views.index, name="index"),
    path("", views.login, name="login"),
    path("login/", views.login, name="login"),
    path("logout/", views.logout, name="logout"),
    path("register/", views.register, name="register"),
    path("main/", views.main, name="main"),
    path("change_master/", views.change_master, name="change_master"),
    path("change_password/", views.change_password, name="change_password"),
    path("logs/", LogView.as_view(), name="logs"),
    path("shared/", SharedView.as_view(), name="shared"),
    path("edit/", EditView.as_view(), name="edit"),
    path("actionlogs/", ActionLogView.as_view(), name="actionlogs"),
    path("records/", RecordsView.as_view(), name="records")
]
