"""
Django settings for tummy_tango_backend project.

Generated by 'django-admin startproject' using Django 4.2.5.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path
from datetime import timedelta

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-0ud%_v%%*!wysi+qsov#r#l)w)zip7zvqyuo3coffz#g0-v33*'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'corsheaders',
    'tummy_tango_app',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'tummy_tango_backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'tummy_tango_backend.wsgi.application'

# Database settings mysql
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': '---Input database name---',  # Replace with your database name
        'USER': '---Input username---',  # Replace with your database user
        'PASSWORD': '---Input password---',  # Replace with your database password
        'HOST': 'localhost',  # Replace with your MySQL host if not running on localhost
        'PORT': '3306',  # Replace with your MySQL port if not the default (3306)
    }
}

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization settings
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Authentication user model
AUTH_USER_MODEL = 'tummy_tango_app.User'

# CORS settings
CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_CREDENTIALS = True

# Rest Framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        # ... other authentication classes if needed
    ),
}

# Django Rest Framework SimpleJWT settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=1),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=1),
    'SLIDING_TOKEN_LIFETIME': timedelta(days=1),
    'SLIDING_TOKEN_REFRESH_ON_LOGIN': True,
    'SLIDING_TOKEN_REFRESH_ON_REFRESH': True,
    'SLIDING_TOKEN_REFRESH_AFTER_LIFETIME': False,
    'SLIDING_TOKEN_LIFETIME_GRACE_PERIOD': timedelta(seconds=60),
    'SLIDING_TOKEN_REFRESH_GRACE_PERIOD': timedelta(seconds=120),
    'SLIDING_TOKEN_ROTATE_REFRESH_TOKENS': False,
    'ALGORITHM': '*****KEY******',
    'SIGNING_KEY': *****KEY******,  # Ensure this matches your Django SECRET_KEY
    'VERIFYING_KEY': None,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_CLAIM': 'user_id',
    'USER_ID_FIELD': 'id',
    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_SLIDING_CLAIM': 'sliding',
    'SLIDING_TOKEN_LIFETIME_CLAIM': 'sliding_exp',
    'SLIDING_TOKEN_REFRESH_SLIDING_CLAIM': 'refresh_sliding',
    'SLIDING_TOKEN_USER_RETRIEVE_BY_CREDENTIALS': 'rest_framework_simplejwt.utils.retrieve_user',
}

# Email configuration settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = '---Input host email here---'  # Your Gmail email address
SENDER_EMAIL = 'Desired Name <---Input sender email here--->'
RECIEVER_EMAIL = ["---Input reciever email here---"]
EMAIL_HOST_PASSWORD = '*****KEY******'  # Your Gmail password or an app-specific password

#Open API Key
OPEN_API_KEY = "*****KEY******"

#Cipher suit Key for Encrypt and Decrypt User data 
CIPHER_SUITE_KEY = "*****KEY******"


