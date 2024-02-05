# celery.py

from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'IebsAnalytics.settings')

app = Celery('IebsAnalytics')

app.config_from_object('django.conf:settings', namespace='CELERY')

# Use Redis as the broker
app.conf.broker_url = 'redis://localhost:6379/0'

# Set broker_connection_retry_on_startup to True
app.conf.broker_connection_retry_on_startup = True

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()
