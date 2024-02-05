"""
Module docstring: Define the configuration for the 'visualizer' app.
"""

from django.apps import AppConfig

class VisualizerConfig(AppConfig):
    """
    VisualizerConfig class extending Django's AppConfig.

    Attributes:
        default_auto_field (str): The default auto field for model field creation.
        name (str): The name of the app.

    Methods:
        No additional methods at the moment.

    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'visualizer'
