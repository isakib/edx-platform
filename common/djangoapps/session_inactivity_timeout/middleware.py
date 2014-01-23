"""
Middleware to auto-expire inactive sessions after N minutes, which is configurable in
settings.

To enable this feature, set in a settings.py:

  SESSION_INACTIVITY_TIMEOUT_IN_MINS = 5

This was taken from StackOverflow (http://stackoverflow.com/questions/14830669/how-to-expire-django-session-in-5minutes)
"""
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib import auth


class SessionInactivityTimeout:
    """
    Middleware class to keep track of activity on a given session
    """
    def process_request(self, request):
        """
        Standard entry point for processing requests in Django
        """
        if not hasattr(request, "user") or not request.user.is_authenticated() :
            #Can't log out if not logged in
            return

        timeout_in_seconds = getattr(settings, "SESSION_INACTIVITY_TIMEOUT_IN_SECONDS", None)

        if timeout_in_seconds:
            try:
                time_since_last_activity = datetime.now() - request.session['last_touch']
                if time_since_last_activity > timedelta(0, timeout_in_seconds, 0):
                  auth.logout(request)
                  del request.session['last_touch']
                  return
            except KeyError:
                pass

        request.session['last_touch'] = datetime.now()
