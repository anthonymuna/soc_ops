from django.contrib.auth import get_user_model
User = get_user_model()
print("Users:", [u.username for u in User.objects.all()])
