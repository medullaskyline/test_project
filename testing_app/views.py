from django.shortcuts import render, HttpResponseRedirect, HttpResponse
from testing_app.models import Category, Page
from testing_app.forms import CategoryForm, UserProfileForm, UserForm
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
# # new from http://ghickman.co.uk/2012/07/22/setup-single-sign-on-in-django-using-google-oauth2.html
# from django.core.urlresolvers import reverse
# from django.contrib import messages
# from django.views.generic.base import View
# from social_auth.backends.exceptions import AuthFailed
# from social_auth.views import complete


# # new from http://ghickman.co.uk/2012/07/22/setup-single-sign-on-in-django-using-google-oauth2.html
# class AuthComplete(View):
#     def get(self, request, *args, **kwargs):
#         backend = kwargs.pop('backend')
#         try:
#             return complete(request, backend, *args, **kwargs)
#         except AuthFailed:
#             messages.error(request, "Your Google Apps domain isn't authorized for this app")
#             return HttpResponseRedirect(reverse('login'))
#
#
# # new from http://ghickman.co.uk/2012/07/22/setup-single-sign-on-in-django-using-google-oauth2.html
# class LoginError(View):
#     def get(self, request, *args, **kwargs):
#         return HttpResponse(status=401)


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