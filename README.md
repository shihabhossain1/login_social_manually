# Manual LinkedIn and Google Login Integration in Django

This guide shows you how to implement manual OAuth2 login with **LinkedIn** and **Google** in a Django project **without using third-party libraries** like `social-auth-app-django`.

---

## 🔧 Prerequisites
- Python & Django installed
- Basic Django project set up
- `requests` library installed:

```bash
pip install requests
```

---

## 📘 LinkedIn Login Integration (Manual OAuth2)

### 🧩 Step 1: Set Up LinkedIn App
1. Go to [https://www.linkedin.com/developers/apps](https://www.linkedin.com/developers/apps)
2. Create a new app.
3. Add the OAuth redirect URL: `http://localhost:8000/linkedin/callback/`
4. Copy the **Client ID** and **Client Secret**.

### ⚙️ Step 2: Add Settings in `settings.py`
```python
LINKEDIN_CLIENT_ID = 'your-client-id'
LINKEDIN_CLIENT_SECRET = 'your-client-secret'
LINKEDIN_REDIRECT_URI = 'http://localhost:8000/linkedin/callback/'
```

### 🌐 Step 3: Add URLs
```python
# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('linkedin/login/', views.linkedin_login, name='linkedin_login'),
    path('linkedin/callback/', views.linkedin_callback, name='linkedin_callback'),
]
```

### 🧠 Step 4: Views Logic (OAuth2)
```python
# views.py
import requests
from django.conf import settings
from django.shortcuts import redirect, render
from django.contrib.auth import login
from django.contrib.auth.models import User

def linkedin_login(request):
    auth_url = (
        'https://www.linkedin.com/oauth/v2/authorization'
        f'?response_type=code&client_id={settings.LINKEDIN_CLIENT_ID}'
        f'&redirect_uri={settings.LINKEDIN_REDIRECT_URI}'
        f'&scope=r_liteprofile r_emailaddress'
    )
    return redirect(auth_url)

def linkedin_callback(request):
    code = request.GET.get('code')
    token_response = requests.post(
        'https://www.linkedin.com/oauth/v2/accessToken',
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': settings.LINKEDIN_REDIRECT_URI,
            'client_id': settings.LINKEDIN_CLIENT_ID,
            'client_secret': settings.LINKEDIN_CLIENT_SECRET,
        }
    )
    access_token = token_response.json().get('access_token')
    headers = {'Authorization': f'Bearer {access_token}'}

    profile = requests.get('https://api.linkedin.com/v2/me', headers=headers).json()
    email_data = requests.get(
        'https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))',
        headers=headers
    ).json()

    email = email_data['elements'][0]['handle~']['emailAddress']
    first_name = profile.get('localizedFirstName')
    last_name = profile.get('localizedLastName')
    linkedin_id = profile.get('id')

    user, created = User.objects.get_or_create(username=linkedin_id, defaults={
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'password': User.objects.make_random_password(),
    })

    login(request, user)
    return redirect('/')
```

### 🔐 Permission Issue Fix
If you get an `unauthorized_scope_error`, make sure the "Sign In with LinkedIn" product is enabled in your LinkedIn App and request access for `r_emailaddress`.

---

## 📕 Google Login Integration (Manual OAuth2)

### 🧩 Step 1: Set Up Google App
1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a project or use existing
3. Navigate to **APIs & Services > Credentials**
4. Create **OAuth 2.0 Client ID** (Web Application)
5. Add redirect URI: `http://localhost:8000/google/callback/`
6. Copy **Client ID** and **Client Secret**

### ⚙️ Step 2: Add Settings in `settings.py`
```python
GOOGLE_CLIENT_ID = 'your-client-id'
GOOGLE_CLIENT_SECRET = 'your-client-secret'
GOOGLE_REDIRECT_URI = 'http://localhost:8000/google/callback/'
```

### 🌐 Step 3: Add URLs
```python
# urls.py
urlpatterns += [
    path('google/login/', views.google_login, name='google_login'),
    path('google/callback/', views.google_callback, name='google_callback'),
]
```

### 🧠 Step 4: Views Logic (OAuth2)
```python
# views.py

def google_login(request):
    auth_url = (
        'https://accounts.google.com/o/oauth2/v2/auth'
        f'?response_type=code&client_id={settings.GOOGLE_CLIENT_ID}'
        f'&redirect_uri={settings.GOOGLE_REDIRECT_URI}'
        f'&scope=openid email profile&state=secureRandomState'
    )
    return redirect(auth_url)

def google_callback(request):
    code = request.GET.get('code')
    token_response = requests.post(
        'https://oauth2.googleapis.com/token',
        data={
            'code': code,
            'client_id': settings.GOOGLE_CLIENT_ID,
            'client_secret': settings.GOOGLE_CLIENT_SECRET,
            'redirect_uri': settings.GOOGLE_REDIRECT_URI,
            'grant_type': 'authorization_code',
        }
    )
    access_token = token_response.json().get('access_token')

    user_info = requests.get(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        headers={'Authorization': f'Bearer {access_token}'}
    ).json()

    email = user_info.get('email')
    first_name = user_info.get('given_name')
    last_name = user_info.get('family_name')
    google_id = user_info.get('sub')

    user, created = User.objects.get_or_create(username=google_id, defaults={
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'password': User.objects.make_random_password(),
    })

    login(request, user)
    return redirect('/')
```

---

## 🖼️ Template Login Buttons
```html
<a href="{% url 'linkedin_login' %}">Login with LinkedIn</a>
<a href="{% url 'google_login' %}">Login with Google</a>
```

---

## ✅ Done!
You now have manual OAuth login using LinkedIn and Google integrated into your Django project.

---

## 🔒 Optional Improvements
- Add `state` validation for CSRF protection
- Handle login failures & expired tokens
- Store more user info (profile picture, etc)
- Add logout button

---

Happy coding! 🚀

