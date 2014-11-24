from django.shortcuts import render, HttpResponseRedirect, HttpResponse
from testing_app.models import Category, Page
from testing_app.forms import CategoryForm, UserProfileForm, UserForm
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required

# from django_sample
import os
import logging
import httplib2

from googleapiclient.discovery import build
# from apiclient.discovery import build
from django.core.urlresolvers import reverse
from django.http import HttpResponseBadRequest
from django.shortcuts import render_to_response
from testing_app.models import CredentialsModel
from test_project import settings
from oauth2client import xsrfutil
from oauth2client.client import flow_from_clientsecrets
from oauth2client.django_orm import Storage

from django.utils.functional import SimpleLazyObject


CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), '..', 'client_secrets_web_app.json')

FLOW = flow_from_clientsecrets(
    CLIENT_SECRETS,
    scope='https://www.googleapis.com/auth/plus.me',
    redirect_uri='http://localhost:8000/testing_app/')


# to do: separate login and user_login pages or views
# ...user_login is supposed to have a User object obtained from request
def user_login(request):
    # if request.method == 'POST':

    # user = # A User object usually obtained from request.
    if not isinstance(request.user, SimpleLazyObject):
        print request.user.date_joined
        print request.user.email
        print request.user.first_name
        print request.user.last_name
        print request.user.is_active
        print request.user.is_superuser
        print request.user.username
                        # model_class, key_name, key_value, property_name
    storage = Storage(CredentialsModel, 'id', request.user, 'credential')

    if type(request.user) is not SimpleLazyObject:  # had to add this
        credential = storage.get()
        print "credential is not a simple lazy object"
    else:
        credential = None
    if credential is None or credential.invalid:
        if credential:
            print "credential " + credential + " is invalid"
        else:
            print "credential is none"
        FLOW.params['state'] = xsrfutil.generate_token(settings.SECRET_KEY, request.user)
        authorize_url = FLOW.step1_get_authorize_url()
        print 'authorize url is ' + authorize_url
        return HttpResponseRedirect(authorize_url)
    else:
        print "credential is valid"
        http = httplib2.Http()
        http = credential.authorize(http)
        service = build("testing_app", "v1", http=http)
        activities = service.activities()
        activity_list = activities.list(collection='public',
                                        userId='me').execute()
        logging.info(activity_list)

    return render_to_response('/testing_app', {
                'activitylist': activity_list,
                })


        # username = request.POST['username']
        # password = request.POST['password']
        # user = authenticate(username=username, password=password)
        #
        # if user:
        #     if user.is_active:
        #         login(request, user)
        #         return HttpResponseRedirect('/testing_app')
        #     else:
        #         return HttpResponseRedirect("Your Testing App account is disabled")
        # else:
        #     print "Invalid login details: {0}, {1}".format(username, password)
        #     return HttpResponse("Invalid login details supplied.")
    # else:
    #     return render(request, 'testing_app/login.html', {})


@login_required
def restricted(request):
    return HttpResponse("Since you're logged in, you can see this text!")

@login_required
def user_logout(request):
    logout(request)
    return HttpResponseRedirect('/testing_app/')


def index(request):
    category_list = Category.objects.order_by('-likes')[:5]
    page_list = Page.objects.order_by('-views')[:5]
    context_dict = {'categories': category_list,
                    'pages': page_list}
    return render(request, 'testing_app/index.html', context_dict)


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

    return render(request, 'testing_app/category.html', context_dict)


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

    # A boolean value for telling the template whether the registration was successful.
    # Set to False initially. Code changes value to True when registration succeeds.
    registered = False

    # If it's a HTTP POST, we're interested in processing form data.
    if request.method == 'POST':
        # Attempt to grab information from the raw form information.
        # Note that we make use of both UserForm and UserProfileForm.
        user_form = UserForm(data=request.POST)
        profile_form = UserProfileForm(data=request.POST)

        # If the two forms are valid...
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

            # Did the user provide a profile picture?
            # If so, we need to get it from the input form and put it in the UserProfile model.
            if 'picture' in request.FILES:
                profile.picture = request.FILES['picture']

            # Now we save the UserProfile model instance.
            profile.save()

            # Update our variable to tell the template registration was successful.
            registered = True

        # Invalid form or forms - mistakes or something else?
        # Print problems to the terminal.
        # They'll also be shown to the user.
        else:
            print user_form.errors, profile_form.errors

    # Not a HTTP POST, so we render our form using two ModelForm instances.
    # These forms will be blank, ready for user input.
    else:
        user_form = UserForm()
        profile_form = UserProfileForm()

    # Render the template depending on the context.
    return render(request,
            'testing_app/register.html',
            {'user_form': user_form, 'profile_form': profile_form, 'registered': registered} )

