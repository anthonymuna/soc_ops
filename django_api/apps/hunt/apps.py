from django.apps import AppConfig

class HuntConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.hunt'

    def ready(self):
        import os
        if os.environ.get('DJANGO_SKIP_WORKER') != '1':
            # Seed hypotheses
            from django.db import connection
            try:
                # Seed only if database table is available
                if 'hunt_hunthypothesis' in connection.introspection.table_names():
                    from .hypotheses import seed_hypotheses
                    seed_hypotheses()
            except Exception as e:
                print(f"[HuntConfig] Failed to seed hypotheses: {e}", flush=True)

            # Start baseline worker
            try:
                from .baseline import start_worker
                start_worker()
            except Exception as e:
                print(f"[HuntConfig] Failed to start baseline worker: {e}", flush=True)
