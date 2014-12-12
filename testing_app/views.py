import os
import httplib2
import logging

from django.shortcuts import render, HttpResponseRedirect, HttpResponse, render_to_response
from django.http import HttpResponseBadRequest
from testing_app.models import Category, Page, CredentialsModel
from testing_app.forms import CategoryForm, UserProfileForm, UserForm
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from oauth2client import xsrfutil
from oauth2client.client import flow_from_clientsecrets
from oauth2client.django_orm import Storage
from apiclient.discovery import build
from test_project import settings
from django.utils.functional import SimpleLazyObject
from identitytoolkit import gitkitclient
# from cookielib import Cookie


# CLIENT_SECRETS, name of a file containing the OAuth 2.0 information for this
# application, including client_id and client_secret, which are found
# on the API Access tab on the Google APIs
# Console <http://code.google.com/apis/console>
CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), '..', 'client_secrets.json')

FLOW = flow_from_clientsecrets(
    CLIENT_SECRETS,
    scope='https://www.googleapis.com/auth/plus.me',
    redirect_uri='http://localhost:8000/testing_app/oauth2callback')  # same as going to auth_return


# def index(request):
#     print 'at the index request.user is ' + str(type(request.user))
#
#     storage = Storage(CredentialsModel, 'id', request.user, 'credential')
#     credential = None
#     if type(request.user) is not SimpleLazyObject:
#         credential = storage.get()
#     if credential is None or credential.invalid:
#         FLOW.params['state'] = xsrfutil.generate_token(settings.SECRET_KEY, request.user)
#         authorize_url = FLOW.step1_get_authorize_url()
#         # authorize_url is the auth_uri from client_secrets with query params...
#         # client_id, redirect_uri, and scope (but not state (opt) or response_type=code (req)??
#         # this HttpResponseRedirect will go first to auth_uri (google), then to redirect uri (the auth_return view)
#         return HttpResponseRedirect(authorize_url)
#     else:
#         http = httplib2.Http()
#         http = credential.authorize(http)
#         service = build("plus", "v1", http=http)
#         activities = service.activities()
#         activitylist = activities.list(collection='public',
#                                        userId='me').execute()
#         logging.info(activitylist)
#         category_list = Category.objects.order_by('-likes')[:5]
#         page_list = Page.objects.order_by('-views')[:5]
#         context_dict = {'categories': category_list,
#                         'pages': page_list,
#                         'activitylist': activitylist
#                         }
#
#         return render_to_response('testing_app/index.html', context_dict)

gitkit_instance = gitkitclient.GitkitClient.FromConfigFile('gitkit-server-config.json')


def index(request):  # this is for gitkitclient

    category_list = Category.objects.order_by('-likes')[:5]
    page_list = Page.objects.order_by('-views')[:5]
    context_dict = {'categories': category_list,
                    'pages': page_list,
                    'userinfo': ''}
    if 'gtoken' in request.COOKIES:
        gitkit_user = gitkit_instance.VerifyGitkitToken(request.COOKIES['gtoken'])
        if gitkit_user:
            # change how user is stored -- maybe id of user in database = user_id as well?

            user = authenticate(username=gitkit_user.email, password=gitkit_user.user_id)
            if user is None: # and gitkit_user.user_id not in global user dictionary
                # in the future, can opt to not log in by removing the gtoken cookie
                # remove gtoken (or session?) cookie by setting its max-age to zero

                user = User.objects.create_user(gitkit_user.email, gitkit_user.email, gitkit_user.user_id)
                print 'made user ' + str(gitkit_user.email) + ' with pw ' + str(gitkit_user.user_id)
            login(request, user)
            context_dict['userinfo'] = str(vars(gitkit_user))
        else:
            logout(request)
    else:
        # if the user has no active session on your site you may redirect to https://yoursite.com/signin?mode=select
        logout(request)
    return render(request, 'testing_app/index.html', context_dict)


# def index(request):  # old
#     category_list = Category.objects.order_by('-likes')[:5]
#     page_list = Page.objects.order_by('-views')[:5]
#     context_dict = {'categories': category_list,
#                     'pages': page_list}
#     return render(request, 'testing_app/index.html', context_dict)


def widget(request):
    return render(request, 'testing_app/widget.html', {})


def auth_return(request):
    # print request
    # problem is that request.user has to be a django.contrib.auth.models.User

    if not xsrfutil.validate_token(settings.SECRET_KEY, request.REQUEST['state'], request.user):
        return HttpResponseBadRequest()
    credential = FLOW.step2_exchange(request.REQUEST)
    # print 'credential.invalid is ' + str(credential.invalid)
    # print 'credential\'s user agent is ' + str(credential.user_agent)

    storage = Storage(CredentialsModel, 'id', request.user, 'credential')

    print 'storage.key_value is ' + str(storage.key_value)
    print 'username is ' + str(request.user.username)
    print 'is superuser is ' + str(request.user.is_superuser)

    storage.put(credential)
    return HttpResponseRedirect("/testing_app/")  # goes back to index view if return HttpResponseRedirect("/testing_app/")


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