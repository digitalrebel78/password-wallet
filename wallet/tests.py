from django.test import TestCase
from django.test.client import RequestFactory
from django.contrib.sessions.middleware import SessionMiddleware

from .views import LogView

from .models import User
from .models import Password
from .models import Logs


class LogViewTest(TestCase):
    
    def setUp(self):
        self.factory = RequestFactory()
        middleware = SessionMiddleware()
        self.request = self.factory.get('/')
        middleware.process_request(self.request)
        self.request.session.save()
        self.view = LogView()
        
    def test_get_ip_address_returns_right_ip_address(self):
        response = self.view.get_ip_address(self.request)
        self.assertEqual(response, '127.0.0.1')

    def test_get_attempts_returns_positive_number_or_zero(self):
        response = self.view.get_attempts(self.request)
        self.assertTrue(response >= 0)

    def test_get_failed_attempts_returns_positive_number_or_zero(self):
        response = self.view.get_failed_attempts(self.request)
        self.assertEqual(response >= 0)

if __name__ == "__main__":
     unittest.main()
