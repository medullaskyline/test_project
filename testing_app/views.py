import os
import httplib2
import logging

from django.shortcuts import render, HttpResponseRedirect, HttpResponse, render_to_response
from django.http import HttpResponseBadRequest
from testing_app.models import Category, Page, CredentialsModel
from testing_app.forms import CategoryForm, UserProfileForm, UserForm
from django.contrib.auth.models import User, AnonymousUser
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from oauth2client import xsrfutil
from oauth2client.client import flow_from_clientsecrets
from oauth2client.django_orm import Storage
from apiclient.discovery import build
from django.contrib.auth.decorators import login_required
from test_project import settings
from django.utils.functional import SimpleLazyObject
from identitytoolkit import gitkitclient
from django.db.models import Max
from django.db import IntegrityError
from random import randint
import base64
import time
import json
import urllib
import urllib2




# CLIENT_SECRETS, name of a file containing the OAuth 2.0 information for this
# application, including client_id and client_secret, which are found
# on the API Access tab on the Google APIs
# Console <http://code.google.com/apis/console>
CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), '..', 'client_secrets.json')

FLOW = flow_from_clientsecrets(
    CLIENT_SECRETS,
    scope='openid email',  # 'https://www.googleapis.com/auth/plus.me',
    redirect_uri='http://localhost:8000/testing_app/oauth2callback')  # same as going to auth_return


def index(request):
    print '\nat the index request.user is ' + str(request.user) + ' with id of ' + str(request.user)

    credential = None
    if request.user.is_authenticated():
        print '\nuser is authenticated '
        storage = Storage(CredentialsModel, 'id', request.user, 'credential')
        credential = storage.get()
    if credential is None or credential.invalid:
        if credential is None:
            print '\ncredential is none'
        else:
            print '\ncredential invalid'
        FLOW.params['state'] = xsrfutil.generate_token(settings.SECRET_KEY, request.user)
        # print '\n flow.params[state] is ' + str(FLOW.params['state'])
        authorize_url = FLOW.step1_get_authorize_url()
        print '\nauthorize_url is ' + str(authorize_url)
        # authorize_url is the auth_uri from client_secrets with query params...
        # client_id, redirect_uri, and scope (but not state (opt) or response_type=code (req)??
        # this HttpResponseRedirect will go first to auth_uri (google), then to redirect uri (the auth_return view)
        return HttpResponseRedirect(authorize_url)
    else:
        print '\nhere, logged in as ' + request.user.first_name
        http = httplib2.Http()
        http = credential.authorize(http)
        service = build("plus", "v1", http=http)
        activities = service.activities()
        activitylist = activities.list(collection='public',
                                       userId='me').execute()
        logging.info(activitylist)
        category_list = Category.objects.order_by('-likes')[:5]
        page_list = Page.objects.order_by('-views')[:5]
        context_dict = {'categories': category_list,
                        'pages': page_list,
                        'activitylist': activitylist
                        }

        return render_to_response('testing_app/index.html', context_dict)


def auth_return(request):
    if not validate_token(settings.SECRET_KEY, request.REQUEST['state'], request.user):
        # used to be xsrfutil.validate_token but apparently problems in source code
        return HttpResponseBadRequest()
    credential = FLOW.step2_exchange(request.REQUEST)

    cred_json = json.loads(credential.to_json())
    email_from_id_token = cred_json["id_token"]["email"]

    url = 'https://www.googleapis.com/oauth2/v1/userinfo?access_token=' + cred_json["access_token"]
    # or https://www.googleapis.com/plus/v1/people/me?access_token=
    req = urllib2.Request(url)
    response = urllib2.urlopen(req)
    # from response get id, email, verified_email, name, given_name, family_name, link, picture, hd
    user_info = {}
    for line in response.readlines():
        line = line.strip()
        if not line or line is '{' or line is '}':
            pass
        else:
            (key, val) = line.split(': ')
            key = key[key.find('"')+1:key.rfind('"')]
            val = val[val.find('"')+1:val.rfind('"')]
            if val == 'true':
                val = True
            if val == 'false':
                val = False
            if key == 'id':
                val = int(val)
            user_info[key] = val
    # print 'user_info is ' + str(user_info)
    id_from_user_info = user_info['id']
    # print '\nid is ' + str(id_from_user_info)

    if cred_json["id_token"]["email_verified"]:
        if request.user.is_authenticated():
            logout(request)
        user = User.objects.get(username=email_from_id_token)

        if user is None:
            print '\nhere'
            User.objects.create_user(username=email_from_id_token, email=email_from_id_token, password=id_from_user_info)
            user.set_password(id_from_user_info)
            user.first_name = user_info['given_name']
            user.last_name = user_info['family_name']
            user.email = email_from_id_token
            user.save()
        user = authenticate(username=email_from_id_token, password=id_from_user_info)
        login(request, user)

        storage = Storage(CredentialsModel, 'id', user, 'credential')
        storage.put(credential)
        return render(request, "/testing_app/")
    else:
        return HttpResponse('email not verified')



    # then get user info from curl https://www.googleapis.com/oauth2/v1/userinfo?access_token= [access token here]
    # when scope is 'openid email', response is
    # {
    # "id": "104512635923656525092",
    # "email": "kiverson@systemsbiology.org",
    # "verified_email": true,
    # "name": "Kelly Iverson",
    # "given_name": "Kelly",
    # "family_name": "Iverson",
    # "link": "https://plus.google.com/104512635923656525092",
    # "picture": "https://lh6.googleusercontent.com/-eSNXFhGK28k/AAAAAAAAAAI/AAAAAAAAAEI/dV80f0ioAHo/photo.jpg",
    # "hd": "systemsbiology.org"
    # }
    # when scope is 'https://www.googleapis.com/auth/plus.me', response is
    # {
    #  "id": "104512635923656525092",
    #  "name": "Kelly Iverson",
    #  "given_name": "Kelly",
    #  "family_name": "Iverson",
    #  "link": "https://plus.google.com/104512635923656525092",
    #  "picture": "https://lh6.googleusercontent.com/-eSNXFhGK28k/AAAAAAAAAAI/AAAAAAAAAEI/dV80f0ioAHo/photo.jpg"
    # }
    # consider trying https://www.googleapis.com/plus/v1/people/<id> (id='me' for currently logged in user)

def validate_token(key, token, user_id):
    if not token:
        return False
    try:
        decoded = base64.urlsafe_b64decode(str(token))
        token_time = long(decoded.split(':')[-1])
    except (TypeError, ValueError):
        return False
    if time.time() - token_time > 60*60:
        return False

    expected_token = xsrfutil.generate_token(key, user_id, when=token_time)

    if len(token) != len(expected_token):
        return False
    different = 0
    for x, y in zip(token, expected_token):
        different |= ord(x) ^ ord(y)
    if different:
        return False

    return True

# gitkit_instance = gitkitclient.GitkitClient.FromConfigFile('gitkit-server-config.json')


# def index(request):  # this is for gitkitclient
#
#     category_list = Category.objects.order_by('-likes')[:5]
#     page_list = Page.objects.order_by('-views')[:5]
#     context_dict = {'categories': category_list,
#                     'pages': page_list,
#                     'userinfo': ''}
#     if 'gtoken' in request.COOKIES:
#         gitkit_user = gitkit_instance.VerifyGitkitToken(request.COOKIES['gtoken'])
#         if gitkit_user:
#             # change how user is stored -- maybe id of user in database = user_id as well?
#             user = authenticate(username=gitkit_user.email, password=gitkit_user.user_id)
#             if user is None:
#                 # and gitkit_user.user_id not in global user dictionary
#                 # in the future, can opt to not log in by removing the gtoken cookie
#                 # remove gtoken (or session?) cookie by setting its max-age to zero
#                 first_name = None
#                 last_name = None
#                 gitkit_user_by_email = gitkit_instance.GetUserByEmail(gitkit_user.email)
#                 if gitkit_user_by_email:
#                     first_name = gitkit_user_by_email.name.split(' ')[0]
#                     last_name = gitkit_user_by_email.name.split(' ')[1]
#                 try:
#                     User.objects.create_user(
#                         id=User.objects.all().aggregate(Max('id'))['id__max']+1,
#                         username=gitkit_user.email,
#                         email=gitkit_user.email,
#                         password=gitkit_user.user_id,
#                         first_name=first_name,
#                         last_name=last_name
#                     )
#                     user = authenticate(username=gitkit_user.email, password=gitkit_user.user_id)
#
#                 except IntegrityError, e:
#                     print '\nerror is ' + str(e)
#                     print 'user id is ' + ' and gitkit id is ' + str(gitkit_user.user_id)
#
#                     return render(request, 'testing_app/index.html', context_dict)
#             context_dict['userinfo'] = str(vars(gitkit_user))
#             login(request, user)
#             # user.save() # ??
#         else:
#             print '\n invalid gtoken'
#             # this shouldn't ever happen
#             logout(request)
#     else:
#         # if the user has no active session on your site you may redirect to https://yoursite.com/signin?mode=select
#         logout(request)
#     return render(request, 'testing_app/index.html', context_dict)


def gitkit_logout(request):
    # this just logs out of django, not google+
    # the javascript on the index.html page logs out of google+ when it sees the django user is logged out
    logout(request)
    # shouldn't have to populate context_dict again -- find alternative
    category_list = Category.objects.order_by('-likes')[:5]
    page_list = Page.objects.order_by('-views')[:5]
    context_dict = {'categories': category_list,
                    'pages': page_list,
                    'userinfo': ''}
    return render(request, 'testing_app/index.html', context_dict)


def widget(request):
    return render(request, 'testing_app/widget.html', {})


def category(request, category_name_slug):
    context_dict = {}
    try:
        category = Category.objects.get(slug=category_name_slug)
        context_dict['category_name'] = category.name

        pages = Page.objects.filter(category=category)
        context_dict['pages'] = pages
        context_dict['category'] = category

    except Category.DoesNotExist:
        pass

    return render(request, 'testing_app/category.html', context_dict)  # when logged in as a django user, with django admin, does a redirect loop


def add_category(request):
    if request.method == 'POST':
        form = CategoryForm(request.POST)

        if form.is_valid():
            form.save(commit=True)
            return index(request)
        else:
            print form.errors

    else:
        form = CategoryForm()

    return render(request, 'testing_app/add_category.html', {'form': form})


def about(request):
    return render(request, 'testing_app/about.html')


def register(request):

    registered = False

    if request.method == 'POST':
        user_form = UserForm(data=request.POST)
        profile_form = UserProfileForm(data=request.POST)

        if user_form.is_valid() and profile_form.is_valid():
            # Save the user's form data to the database.
            user = user_form.save()

            # Now we hash the password with the set_password method.
            # Once hashed, we can update the user object.
            user.set_password(user.password)
            user.save()

            # Now sort out the UserProfile instance.
            # Since we need to set the user attribute ourselves, we set commit=False.
            # This delays saving the model until we're ready to avoid integrity problems.
            profile = profile_form.save(commit=False)
            profile.user = user
            if 'picture' in request.FILES:
                profile.picture = request.FILES['picture']

            profile.save()
            registered = True

        else:
            print user_form.errors, profile_form.errors

    else:
        user_form = UserForm()
        profile_form = UserProfileForm()

    return render(request,
            'testing_app/register.html',
            {'user_form': user_form, 'profile_form': profile_form, 'registered': registered})


def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)

        if user:
            if user.is_active:
                login(request, user)
                return HttpResponseRedirect('/testing_app')
            else:
                return HttpResponseRedirect("Your Testing App account is disabled")
        else:
            print "Invalid login details: {0}, {1}".format(username, password)
            return HttpResponse("Invalid login details supplied.")
    else:
        return render(request, 'testing_app/login.html', {})


@login_required
def restricted(request):
    return HttpResponse("Since you're logged in, you can see this text!")

@login_required
def user_logout(request):
    logout(request)
    return HttpResponseRedirect('/testing_app/')