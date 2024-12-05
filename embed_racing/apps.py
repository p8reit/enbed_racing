from django.apps import AppConfig


class EmbedRacingConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'embed_racing'


def ready(self):
        import embed_racing.auth_hooks  # Ensures the menu hooks are registered when the app is ready