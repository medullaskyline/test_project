from django.conf.urls import patterns, url
from testing_app import views
from django.contrib.auth.views import login

urlpatterns = patterns('',
                       url(r'^$', views.index, name='index'),
                       url(r'^about', views.about, name='about'),
                       url(r'^category/(?P<category_name_slug>[\w\-]+)/$', views.category, name='category'),
                       url(r'^add_category/$', views.add_category, name='add_category'),
                       url(r'^register/$', views.register, name='register'),
                       url(r'^login/$', views.user_login, name='login'),
                       url(r'^restricted/', views.restricted, name='restricted'),
                       url(r'^logout/$', views.user_logout, name='logout'),
                       url(r'^gitkit_logout/$', views.gitkit_logout, name='logout'),
                       url(r'^oauth2callback', views.auth_return, name='auth_return'),
                       )