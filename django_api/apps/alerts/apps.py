from django.apps import AppConfig

class AlertsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.alerts'

    def ready(self):
        import os
        print("[AlertsConfig] ready() called. RUN_MAIN=" + str(os.environ.get('RUN_MAIN')) + ", DJANGO_SKIP_WORKER=" + str(os.environ.get('DJANGO_SKIP_WORKER')), flush=True)
        # Only start in the main process, not in migrations or management commands
        if os.environ.get('RUN_MAIN') != 'true' and os.environ.get('DJANGO_SKIP_WORKER') != '1':
            print("[AlertsConfig] Starting ThreatEnrichmentWorker...", flush=True)
            from .enrichment import start_worker
            start_worker()
