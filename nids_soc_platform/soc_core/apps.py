from django.apps import AppConfig

class SocCoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'soc_core'

    def ready(self):
        # Se execută o singură dată când Django este inițializat complet
        from .views import get_ml_components
        try:
            get_ml_components()
        except Exception:
            pass