# Manual LinkedIn, Google, Facebook, and GitHub Login Integration in Django

This guide shows you how to implement manual OAuth2 login with **LinkedIn**, **Google**, **Facebook**, and **GitHub** in a Django project **without using third-party libraries** like `social-auth-app-django`. 

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
    linkedin_auth_url = "https://www.linkedin.com/oauth/v2/authorization"
    redirect_uri = settings.LINKEDIN_REDIRECT_URI
    client_id = settings.LINKEDIN_CLIENT_ID
    scope = "r_liteprofile r_emailaddress"

    auth_url = (
        f"{linkedin_auth_url}?response_type=code&client_id={client_id}"
        f"&redirect_uri={redirect_uri}&scope={scope}"
    )
    return redirect(auth_url)

# Step 2: Handle LinkedIn Callback
def linkedin_callback(request):
    code = request.GET.get('code')
    if not code:
        return render(request, 'error.html', {"message": "Authorization failed."})

    # Exchange code for access token
    token_url = "https://www.linkedin.com/oauth/v2/accessToken"
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': settings.LINKEDIN_REDIRECT_URI,
        'client_id': settings.LINKEDIN_CLIENT_ID,
        'client_secret': settings.LINKEDIN_CLIENT_SECRET,
    }
    response = requests.post(token_url, data=data)
    access_token = response.json().get("access_token")

    if not access_token:
        return render(request, 'error.html', {"message": "Failed to get access token."})

    # Get user's profile
    headers = {'Authorization': f'Bearer {access_token}'}
    
    # Basic profile
    profile_res = requests.get('https://api.linkedin.com/v2/me', headers=headers)
    profile = profile_res.json()

    # Email
    email_res = requests.get(
        'https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))',
        headers=headers
    )
    email_data = email_res.json()
    email = email_data['elements'][0]['handle~']['emailAddress']

    # Get or create user
    linkedin_id = profile.get('id')
    first_name = profile.get('localizedFirstName')
    last_name = profile.get('localizedLastName')

    try:
        user = User.objects.get(username=linkedin_id)
    except User.DoesNotExist:
        user = User.objects.create_user(
            username=linkedin_id,
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=User.objects.make_random_password()
        )

    auth_login(request, user)
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
    base_url = "https://accounts.google.com/o/oauth2/v2/auth"
    redirect_uri = settings.GOOGLE_REDIRECT_URI
    client_id = settings.GOOGLE_CLIENT_ID
    scope = "openid email profile"
    response_type = "code"
    state = "secureRandomState123"  # optionally generate one and store it in session

    auth_url = (
        f"{base_url}?response_type={response_type}&client_id={client_id}"
        f"&redirect_uri={redirect_uri}&scope={scope}&state={state}"
    )
    return redirect(auth_url)


def google_callback(request):
    code = request.GET.get('code')

    token_url = 'https://oauth2.googleapis.com/token'
    data = {
        'code': code,
        'client_id': settings.GOOGLE_CLIENT_ID,
        'client_secret': settings.GOOGLE_CLIENT_SECRET,
        'redirect_uri': settings.GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code',
    }

    token_response = requests.post(token_url, data=data)
    token_data = token_response.json()
    access_token = token_data.get('access_token')
    id_token = token_data.get('id_token')

    # Get user info
    user_info_url = 'https://www.googleapis.com/oauth2/v3/userinfo'
    headers = {'Authorization': f'Bearer {access_token}'}
    user_info_response = requests.get(user_info_url, headers=headers)
    user_info = user_info_response.json()

    # Extract info
    email = user_info.get('email')
    first_name = user_info.get('given_name')
    last_name = user_info.get('family_name')
    sub = user_info.get('sub')  # Unique Google ID

    # Get or create user
    try:
        user = User.objects.get(username=sub)
    except User.DoesNotExist:
        user = User.objects.create_user(
            username=sub,
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=User.objects.make_random_password()
        )

    login(request, user)
    return redirect('/')
```

---


## 🟦 Facebook Login (Manual OAuth2)

### Setup Steps
1. Go to [Meta Developers](https://developers.facebook.com/)
2. Create a new app → Facebook Login → Web
3. Set redirect URI: `http://localhost:8000/facebook/callback/`
4. Add to `settings.py`:
```python
FACEBOOK_CLIENT_ID = 'your-client-id'
FACEBOOK_CLIENT_SECRET = 'your-client-secret'
FACEBOOK_REDIRECT_URI = 'http://localhost:8000/facebook/callback/'
```

### Views Example
```python
def facebook_login(request):
    auth_url = (
        'https://www.facebook.com/v12.0/dialog/oauth'
        f'?client_id={settings.FACEBOOK_CLIENT_ID}'
        f'&redirect_uri={settings.FACEBOOK_REDIRECT_URI}'
        '&scope=email'
    )
    return redirect(auth_url)

def facebook_callback(request):
    code = request.GET.get('code')
    token_url = f"https://graph.facebook.com/v12.0/oauth/access_token"
    response = requests.get(token_url, params={
        'client_id': settings.FACEBOOK_CLIENT_ID,
        'client_secret': settings.FACEBOOK_CLIENT_SECRET,
        'redirect_uri': settings.FACEBOOK_REDIRECT_URI,
        'code': code
    })
    access_token = response.json().get('access_token')

    user_info = requests.get(
        f'https://graph.facebook.com/me?fields=id,name,email&access_token={access_token}'
    ).json()

    email = user_info.get('email')
    name = user_info.get('name')
    facebook_id = user_info.get('id')

    user, created = User.objects.get_or_create(username=facebook_id, defaults={
        'first_name': name.split()[0],
        'last_name': name.split()[-1],
        'email': email,
        'password': User.objects.make_random_password(),
    })
    login(request, user)
    return redirect('/')
```

---

## 🐙 GitHub Login (Manual OAuth2)

### Setup Steps
1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Create a new OAuth App
3. Set callback: `http://localhost:8000/github/callback/`
4. Add to `settings.py`:
```python
GITHUB_CLIENT_ID = 'your-client-id'
GITHUB_CLIENT_SECRET = 'your-client-secret'
GITHUB_REDIRECT_URI = 'http://localhost:8000/github/callback/'
```

### Views Example
```python
def github_login(request):
    auth_url = (
        f'https://github.com/login/oauth/authorize?client_id={settings.GITHUB_CLIENT_ID}'
        f'&redirect_uri={settings.GITHUB_REDIRECT_URI}&scope=user:email'
    )
    return redirect(auth_url)

def github_callback(request):
    code = request.GET.get('code')
    token_response = requests.post(
        'https://github.com/login/oauth/access_token',
        headers={'Accept': 'application/json'},
        data={
            'client_id': settings.GITHUB_CLIENT_ID,
            'client_secret': settings.GITHUB_CLIENT_SECRET,
            'code': code,
            'redirect_uri': settings.GITHUB_REDIRECT_URI
        }
    )
    access_token = token_response.json().get('access_token')

    user_info = requests.get(
        'https://api.github.com/user',
        headers={'Authorization': f'token {access_token}'}
    ).json()

    email = user_info.get('email') or f"{user_info.get('login')}@github.com"
    github_id = str(user_info.get('id'))
    name = user_info.get('name') or user_info.get('login')

    user, created = User.objects.get_or_create(username=github_id, defaults={
        'first_name': name.split()[0],
        'last_name': name.split()[-1] if len(name.split()) > 1 else '',
        'email': email,
        'password': User.objects.make_random_password(),
    })
    login(request, user)
    return redirect('/')
```

---
```
urlpatterns = [
    # LinkedIn
    path('linkedin/login/', views.linkedin_login, name='linkedin_login'),
    path('linkedin/callback/', views.linkedin_callback, name='linkedin_callback'),

    # Google
    path('google/login/', views.google_login, name='google_login'),
    path('google/callback/', views.google_callback, name='google_callback'),

    # Facebook
    path('facebook/login/', views.facebook_login, name='facebook_login'),
    path('facebook/callback/', views.facebook_callback, name='facebook_callback'),

    # GitHub
    path('github/login/', views.github_login, name='github_login'),
    path('github/callback/', views.github_callback, name='github_callback'),
```  
---

## 🖼️ Template Login Buttons
```html
<a href="{% url 'linkedin_login' %}">Login with LinkedIn</a>
<a href="{% url 'google_login' %}">Login with Google</a>
<a href="{% url 'facebook_login' %}">Login with Facebook</a>
<a href="{% url 'github_login' %}">Login with GitHub</a>
```

---

## ✅ Done!
You now have manual OAuth login using LinkedIn, Google, Facebook, and GitHub integrated into your Django project.

---

## 🔒 Optional Improvements
- Add `state` validation for CSRF protection
- Handle login failures & expired tokens
- Store more user info (profile picture, etc)
- Add logout button

---

Happy coding! 🚀





