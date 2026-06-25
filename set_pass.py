from django.contrib.auth import get_user_model
User = get_user_model()
u = User.objects.get(username='admin')
u.set_password('Admin@1234!')
u.is_superuser = True
u.is_staff = True
u.save()
print('Password set successfully.')
